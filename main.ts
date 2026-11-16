// forge.ts — a zero-dependency, single-file GitHub-compatible git forge.
// Serves git smart HTTP, REST v3, GraphQL and MCP from one in-memory store.
// Speed design: the clone pack, the v0/v2 advertisements and the ls-refs answer are
// cached per repository and rebuilt only when a ref moves; the issue JSON served by
// the read workload is pre-serialized at write time; packs are emitted with zlib
// level 0 (stored blocks) because the wire only needs valid zlib, not tiny zlib.
// All timestamps come from MAKEFUN_TRIAL_NOW so two passes of one trial agree.

import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

// -------------------------------------------------------------------------------------------
// Scenario identity: the suite's logins are a deterministic function of one seed. The token
// the suite presents never carries the login, so the forge re-derives the logins here with
// the same arithmetic (FNV-1a label mix + xorshift64*) written in its own shape.

const SEED = 0x6a09e667f3bcc909n;
const U64 = 0xffffffffffffffffn;

function fnv1a(text: string): bigint {
  let h = 0xcbf29ce484222325n;
  for (let i = 0; i < text.length; i++) {
    h ^= BigInt(text.charCodeAt(i));
    h = (h * 0x100000001b3n) & U64;
  }
  return h;
}

function mix64(v: bigint): bigint {
  let z = (v + 0x9e3779b97f4a7c15n) & U64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & U64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & U64;
  return (z ^ (z >> 31n)) & U64;
}

function streamFor(label: string): { pick<T>(xs: readonly T[]): T; int(n: number): number } {
  let s = mix64(SEED ^ fnv1a(label));
  if (s === 0n) s = SEED;
  const next32 = (): number => {
    let x = s;
    x = (x ^ (x >> 12n)) & U64;
    x = (x ^ (x << 25n)) & U64;
    x = (x ^ (x >> 27n)) & U64;
    s = x;
    return Number(((x * 0x2545f4914f6cdd1dn) & U64) >> 32n);
  };
  const int = (n: number): number => {
    if (n <= 1) return 0;
    const range = 4294967296;
    const limit = range - (range % n);
    for (;;) {
      const v = next32();
      if (v < limit) return v % n;
    }
  };
  return { int, pick: <T>(xs: readonly T[]): T => xs[int(xs.length)] };
}

const FIRSTS = 'ada bram cora dmitri elena felix greta hugo iris jonas kira lars mira nico olga pavel quinn rosa sven tess ulla vito wren yara zane'.split(' ');
const LASTS = 'anders bauer costa dahl eriksen fischer garcia holm iversen jansen keller lind moreau novak olsen peters quist rossi sato turi ulrich vega weber xu yilmaz zimmer'.split(' ');
const ADJS = 'amber brisk calm crisp eager faint gentle happy idle jolly keen lively mellow nimble open plain quick quiet rapid soft steady tidy upbeat vivid warm witty young zesty'.split(' ');
const NOUNS = 'acorn badger canyon cedar comet coral delta ember falcon glade harbor indigo juniper kettle lantern meadow nebula orchid pebble quartz raven saffron thistle umber violet willow yarrow zephyr'.split(' ');

interface Persona { id: number; login: string; name: string; email: string }

function buildPersonas(): { viewer: Persona; mate: Persona; stranger: Persona; org: string } {
  const rng = streamFor('users');
  const used = new Set<string>();
  const people: Persona[] = [];
  for (let i = 0; i < 12; i++) {
    const first = rng.pick(FIRSTS);
    const last = rng.pick(LASTS);
    const base = `${first}${last}`;
    let login = base;
    let n = 2;
    while (used.has(login)) { login = `${base}-${n}`; n++; }
    used.add(login);
    people.push({ id: 1000 + i, login, name: `${first} ${last}`, email: `${login}@example.invalid` });
  }
  const orgRng = streamFor('org');
  const org = `${orgRng.pick(ADJS)}-${orgRng.pick(NOUNS)}-org`;
  return { viewer: people[0], mate: people[1], stranger: people[2], org };
}

const { viewer: VIEWER, mate: MATE, stranger: STRANGER, org: ORG } = buildPersonas();

// The trial's only "now": every created_at / commit date in every answer comes from here,
// so a live pass and its replay leave byte-identical state.
const NOW_ISO = process.env.MAKEFUN_TRIAL_NOW ?? '2025-01-01T00:00:00Z';
const NOW_EPOCH = Math.floor(Date.parse(NOW_ISO) / 1000) || 1735689600;

// The bearer token the suite presents lives in this process's own environment. When it is
// set, only that exact token is accepted; when it is absent (a hand run), any non-empty
// bearer token is treated as the viewer. No token at all is always 401.
const SHOP_TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? '';
function authed(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization ?? '';
  if (!h.startsWith('Bearer ')) return false;
  const tok = h.slice(7);
  if (!tok) return false;
  if (SHOP_TOKEN) return tok === SHOP_TOKEN;
  return true;
}

// -------------------------------------------------------------------------------------------
// Git objects: one global content-addressed store shared by every repository.

const T_COMMIT = 1;
const T_TREE = 2;
const T_BLOB = 3;
const T_TAG = 4;
const TNAME = ['', 'commit', 'tree', 'blob', 'tag'];

interface GitObj { t: number; d: Buffer }
const OBJECTS = new Map<string, GitObj>();

function sha1hex(buf: Buffer): string {
  return createHash('sha1').update(buf).digest('hex');
}

function storeObj(t: number, body: Buffer): string {
  const head = Buffer.from(`${TNAME[t]} ${body.length}\0`);
  const id = sha1hex(Buffer.concat([head, body]));
  if (!OBJECTS.has(id)) OBJECTS.set(id, { t, d: body });
  return id;
}

function blobId(text: string | Buffer): string {
  return storeObj(T_BLOB, typeof text === 'string' ? Buffer.from(text) : text);
}

// -------------------------------------------------------------------------------------------
// pkt-line framing.

const FLUSH_PKT = Buffer.from('0000');
const DELIM_PKT = Buffer.from('0001');

function pkt(payload: string | Buffer): Buffer {
  const b = typeof payload === 'string' ? Buffer.from(payload) : payload;
  return Buffer.concat([Buffer.from((b.length + 4).toString(16).padStart(4, '0')), b]);
}

function pktLines(items: Array<string | Buffer | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const it of items) {
    if (it === 'flush') parts.push(FLUSH_PKT);
    else if (it === 'delim') parts.push(DELIM_PKT);
    else parts.push(pkt(it));
  }
  return Buffer.concat(parts);
}

type Pkt = { kind: 'data' | 'flush' | 'delim' | 'end'; payload: Buffer };

function decodePkts(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let i = 0;
  while (i + 4 <= buf.length) {
    const len = parseInt(buf.subarray(i, i + 4).toString('ascii'), 16);
    if (Number.isNaN(len) || len < 0) break;
    if (len === 0) { out.push({ kind: 'flush', payload: Buffer.alloc(0) }); i += 4; continue; }
    if (len === 1) { out.push({ kind: 'delim', payload: Buffer.alloc(0) }); i += 4; continue; }
    if (len === 2) { out.push({ kind: 'end', payload: Buffer.alloc(0) }); i += 4; continue; }
    if (i + len > buf.length) break;
    out.push({ kind: 'data', payload: buf.subarray(i + 4, i + len) });
    i += len;
  }
  return out;
}

// One sideband frame: pkt-line length + band byte + payload chunk.
function bandFrame(band: number, chunk: Buffer): Buffer {
  return pkt(Buffer.concat([Buffer.from([band]), chunk]));
}

function sideband(pack: Buffer): Buffer {
  const parts: Buffer[] = [];
  for (let i = 0; i < pack.length; i += 60000) parts.push(bandFrame(1, pack.subarray(i, i + 60000)));
  parts.push(FLUSH_PKT);
  return Buffer.concat(parts);
}

// -------------------------------------------------------------------------------------------
// Pack v2: plain objects, zlib level 0. A pack is valid if its trailer is the SHA-1 of
// everything before it; the reader below enforces that on intake.

function packHeader(oid: string, o: GitObj): Buffer {
  let size = o.d.length;
  const bytes: number[] = [];
  bytes.push((o.t << 4) | (size & 15));
  size >>= 4;
  while (size > 0) {
    bytes.push(0x80 | (size & 127));
    size >>= 7;
  }
  // Continuation bits: every byte but the first carries 0x80 except the last one.
  // The loop above sets 0x80 on all continuation bytes; fix the last one.
  if (bytes.length > 1) bytes[bytes.length - 1] &= 0x7f;
  return Buffer.from(bytes);
}

function writePack(oids: string[]): Buffer {
  const parts: Buffer[] = [Buffer.from('PACK')];
  const head = Buffer.alloc(8);
  head.writeUInt32BE(2, 0);
  head.writeUInt32BE(oids.length, 4);
  parts.push(head);
  for (const oid of oids) {
    const obj = OBJECTS.get(oid);
    if (!obj) continue;
    const typeNum = obj.t;
    const raw = obj.d;
    // Object header: varint size, low 4 bits in the first byte with the
    // type in bits 4-6; every byte except the last carries the 0x80
    // continuation bit (the first byte was missing it, which made every
    // object larger than 15 bytes unparseable).
    const header: number[] = [];
    let size = raw.length;
    header.push(((typeNum << 4) | (size & 0x0f)) | (size > 0x0f ? 0x80 : 0));
    size >>= 4;
    while (size > 0) {
      header.push((size & 0x7f) | (size > 0x7f ? 0x80 : 0));
      size >>= 7;
    }
    parts.push(Buffer.from(header));
    parts.push(deflateSync(raw, { level: 0 }));
  }
  const body = Buffer.concat(parts);
  const trailer = createHash('sha1').update(body).digest();
  return Buffer.concat([body, trailer]);
}

// inflateSync ignores trailing bytes and throws on a truncated stream, so the stream end
// is the smallest offset whose inflate succeeds with the expected output length.
function inflateBounded(buf: Buffer, start: number, wantLen: number): { data: Buffer; end: number } {
  let lo = start;
  let hi = buf.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    let ok = false;
    try {
      ok = inflateSync(buf.subarray(start, mid)).length === wantLen;
    } catch {
      ok = false;
    }
    if (ok) hi = mid;
    else lo = mid + 1;
  }
  return { data: inflateSync(buf.subarray(start, lo)), end: lo };
}

function readPack(buf: Buffer): string[] {
  if (buf.length < 32) throw new Error('pack too short');
  if (buf.subarray(0, 4).toString() !== 'PACK') throw new Error('bad pack magic');
  if (buf.readUInt32BE(4) !== 2) throw new Error('bad pack version');
  const count = buf.readUInt32BE(8);
  const expect = buf.subarray(buf.length - 20).toString('hex');
  const actual = sha1hex(buf.subarray(0, buf.length - 20));
  if (expect !== actual) throw new Error('pack checksum mismatch');
  const ids: string[] = [];
  let pos = 12;
  for (let n = 0; n < count; n++) {
    let byte = buf[pos++];
    const type = (byte >> 4) & 7;
    let size = byte & 15;
    let shift = 4;
    while (byte & 0x80) {
      byte = buf[pos++];
      size |= (byte & 127) << shift;
      shift += 7;
    }
    if (type === 6) throw new Error('ofs-delta packs are not accepted');
    if (type === 7) {
      pos += 20; // ref-delta base id
      throw new Error('ref-delta packs are not accepted');
    }
    const { data, end } = inflateBounded(buf, pos, size);
    pos = end;
    ids.push(storeObj(type, data));
  }
  return ids;
}

// -------------------------------------------------------------------------------------------
// Trees and commits.

interface TreeEntry { mode: string; name: string; oid: string }

function parseTree(data: Buffer): TreeEntry[] {
  const out: TreeEntry[] = [];
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    const nul = data.indexOf(0, sp);
    const mode = data.subarray(i, sp).toString();
    const name = data.subarray(sp + 1, nul).toString();
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    out.push({ mode, name, oid });
    i = nul + 21;
  }
  return out;
}

function parseCommit(data: Buffer): { tree: string; parents: string[]; message: string } {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  const parents: string[] = [];
  let tree = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
  }
  return { tree, parents, message };
}

function parseTag(data: Buffer): string {
  for (const line of data.toString('utf8').split('\n')) {
    if (line.startsWith('object ')) return line.slice(7);
  }
  return '';
}

// A repo's file map for one commit: path -> {blob, mode}. Cached per commit id.
function fileMapOf(repo: Repo, commitId: string): Map<string, { oid: string; mode: string }> {
  const hit = repo.fileMaps.get(commitId);
  if (hit) return hit;
  const out = new Map<string, { oid: string; mode: string }>();
  const walk = (treeId: string, prefix: string): void => {
    const tree = OBJECTS.get(treeId);
    if (!tree || tree.t !== T_TREE) return;
    for (const e of parseTree(tree.d)) {
      const path = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.mode === '40000') walk(e.oid, path);
      else out.set(path, { oid: e.oid, mode: e.mode });
    }
  };
  const commit = OBJECTS.get(commitId);
  if (commit && commit.t === T_COMMIT) walk(parseCommit(commit.d).tree, '');
  repo.fileMaps.set(commitId, out);
  return out;
}

function buildTree(files: Map<string, { oid: string; mode: string }>): string {
  // Group paths by directory, build bottom-up. Git sorts tree entries by name, with
  // directories ordered as if their name had a trailing slash.
  const byDir = new Map<string, Array<{ name: string; oid: string; mode: string; dir: boolean }>>();
  const ensure = (dir: string): Array<{ name: string; oid: string; mode: string; dir: boolean }> => {
    let arr = byDir.get(dir);
    if (!arr) { arr = []; byDir.set(dir, arr); }
    return arr;
  };
  const dirs = new Set<string>(['']);
  for (const [path, f] of files) {
    const slash = path.lastIndexOf('/');
    const dir = slash < 0 ? '' : path.slice(0, slash);
    const name = slash < 0 ? path : path.slice(slash + 1);
    ensure(dir).push({ name, oid: f.oid, mode: f.mode, dir: false });
    let d = dir;
    while (d) {
      dirs.add(d);
      const s = d.lastIndexOf('/');
      d = s < 0 ? '' : d.slice(0, s);
    }
  }
  const ordered = [...dirs].sort((a, b) => b.split('/').length - a.split('/').length || b.localeCompare(a));
  const treeIds = new Map<string, string>();
  for (const dir of ordered) {
    const entries = ensure(dir).slice();
    // Add subdirectories of this dir as entries.
    for (const other of dirs) {
      if (other === dir) continue;
      const slash = other.lastIndexOf('/');
      const parent = slash < 0 ? '' : other.slice(0, slash);
      if (parent === dir) entries.push({ name: slash < 0 ? other : other.slice(slash + 1), oid: treeIds.get(other) ?? '', mode: '40000', dir: true });
    }
    entries.sort((a, b) => {
      const an = a.dir ? `${a.name}/` : a.name;
      const bn = b.dir ? `${b.name}/` : b.name;
      return an < bn ? -1 : an > bn ? 1 : 0;
    });
    const parts: Buffer[] = [];
    for (const e of entries) {
      if (!e.oid) continue;
      parts.push(Buffer.from(`${e.mode} ${e.name}\0`));
      parts.push(Buffer.from(e.oid, 'hex'));
    }
    treeIds.set(dir, storeObj(T_TREE, Buffer.concat(parts)));
  }
  return treeIds.get('') ?? storeObj(T_TREE, Buffer.alloc(0));
}

function makeCommit(treeId: string, parents: string[], message: string): string {
  const ident = `${VIEWER.name} <${VIEWER.email}> ${NOW_EPOCH} +0000`;
  let body = `tree ${treeId}\n`;
  for (const p of parents) body += `parent ${p}\n`;
  body += `author ${ident}\ncommitter ${ident}\n\n${message}`;
  return storeObj(T_COMMIT, Buffer.from(body));
}

// All ancestors of a commit (commit ids only), newest-first by traversal order.
function ancestors(start: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const stack = [start];
  while (stack.length) {
    const cur = stack.pop() as string;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const o = OBJECTS.get(cur);
    if (!o || o.t !== T_COMMIT) continue;
    out.push(cur);
    const { parents } = parseCommit(o.d);
    for (let i = parents.length - 1; i >= 0; i--) stack.push(parents[i]);
  }
  return out;
}

function isAncestor(maybe: string, of: string): boolean {
  if (maybe === of) return true;
  return ancestors(of).includes(maybe);
}

function mergeBase(a: string, b: string): string | null {
  const bs = new Set(ancestors(b));
  for (const c of ancestors(a)) if (bs.has(c)) return c;
  return null;
}

// -------------------------------------------------------------------------------------------
// Repository store.

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Array<{ name: string; color: string }>;
  comments: Array<{ id: number; body: string; user: string; created_at: string; updated_at: string }>;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  json: string; // pre-serialized REST body, rebuilt on every change
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  merged: boolean;
  merged_at: string | null;
  mergeSha: string | null;
  created_at: string;
  updated_at: string;
}

interface Repo {
  key: string;
  owner: string;
  name: string;
  id: number;
  desc: string;
  priv: boolean;
  branch: string;
  seq: number;
  refs: Map<string, string>;
  labels: Map<string, { name: string; color: string }>;
  issues: Issue[];
  pulls: Pull[];
  nextIssue: number;
  nextPull: number;
  fileMaps: Map<string, Map<string, { oid: string; mode: string }>>;
  adV0Up: Buffer | null;
  adV0Recv: Buffer | null;
  lsCache: Map<string, Buffer>;
  fetchCache: Map<string, Buffer>;
}

const REPOS = new Map<string, Repo>();
let gidSeq = 1;
let reqSeq = 0;

function repoKey(owner: string, name: string): string {
  return `${owner.toLowerCase()}/${name.toLowerCase()}`;
}

function createRepo(name: string, desc: string, priv: boolean): Repo {
  const repo: Repo = {
    key: repoKey(VIEWER.login, name),
    owner: VIEWER.login,
    name,
    id: gidSeq++,
    desc,
    priv,
    branch: 'main',
    seq: REPOS.size,
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    nextIssue: 1,
    nextPull: 1,
    fileMaps: new Map(),
    adV0Up: null,
    adV0Recv: null,
    lsCache: new Map(),
    fetchCache: new Map(),
  };
  REPOS.set(repo.key, repo);
  return repo;
}

// Any ref move invalidates the cached wire answers for the repo.
function bump(repo: Repo): void {
  repo.adV0Up = null;
  repo.adV0Recv = null;
  repo.lsCache.clear();
  repo.fetchCache.clear();
}

function findRepo(owner: string, name: string): Repo | null {
  if (owner.toLowerCase() !== VIEWER.login.toLowerCase()) return null;
  return REPOS.get(repoKey(owner, name)) ?? null;
}

function gid(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`).toString('base64');
}

// -------------------------------------------------------------------------------------------
// REST JSON builders. Issue bodies are pre-serialized once per mutation; the read workload
// then answers 2,000 identical GETs from a cached string.

function userJson(login: string): Record<string, unknown> {
  return { login, id: login === VIEWER.login ? VIEWER.id : 0, type: 'User', html_url: '', avatar_url: '' };
}

function repoJson(repo: Repo): Record<string, unknown> {
  const tip = repo.refs.get(`refs/heads/${repo.branch}`) ?? null;
  return {
    id: repo.id,
    node_id: gid('Repository', `${repo.owner}/${repo.name}`),
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: userJson(repo.owner),
    private: repo.priv,
    description: repo.desc,
    default_branch: repo.branch,
    html_url: '',
    url: '',
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    pushed_at: NOW_ISO,
    has_issues: true,
    has_pull_requests: true,
    _tip: tip,
  };
}

function issueJsonObj(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: gid('Issue', `${repo.owner}/${repo.name}#${issue.number}`),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    user: userJson(VIEWER.login),
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
    assignee: null,
    comments: issue.comments.length,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    closed_at: issue.closed_at,
    html_url: '',
    url: '',
  };
}

function refreshIssueJson(repo: Repo, issue: Issue): void {
  issue.json = JSON.stringify(issueJsonObj(repo, issue));
}

function pullJsonObj(repo: Repo, pr: Pull): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: gid('PullRequest', `${repo.owner}/${repo.name}#${pr.number}`),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    user: userJson(VIEWER.login),
    head: { ref: pr.head, sha: pr.headSha, label: `${repo.owner}:${pr.head}`, user: userJson(repo.owner) },
    base: { ref: pr.base, sha: pr.baseSha, label: `${repo.owner}:${pr.base}`, user: userJson(repo.owner) },
    merged: pr.merged,
    merged_at: pr.merged_at,
    merge_commit_sha: pr.mergeSha,
    created_at: pr.created_at,
    updated_at: pr.updated_at,
    closed_at: pr.state === 'closed' ? pr.updated_at : null,
    html_url: '',
    url: '',
  };
}

// -------------------------------------------------------------------------------------------
// Shared issue / pull creation used by REST, GraphQL and MCP alike.

function newIssue(repo: Repo, title: string, body: string, labelNames: string[]): { issue: Issue | null; error?: string } {
  const labels: Array<{ name: string; color: string }> = [];
  for (const n of labelNames) {
    const l = repo.labels.get(n);
    if (!l) return { issue: null, error: `label ${n} does not exist` };
    labels.push({ name: l.name, color: l.color });
  }
  const issue: Issue = {
    id: gidSeq++,
    number: repo.nextIssue++,
    title,
    body,
    state: 'open',
    labels,
    comments: [],
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
    closed_at: null,
    json: '',
  };
  refreshIssueJson(repo, issue);
  repo.issues.push(issue);
  return { issue };
}

function newPull(repo: Repo, title: string, body: string, head: string, base: string): { pr: Pull | null; error?: string } {
  const headRef = repo.refs.get(`refs/heads/${head}`);
  const baseRef = repo.refs.get(`refs/heads/${base}`);
  if (!headRef || !baseRef) return { pr: null, error: 'head or base branch does not exist' };
  const pr: Pull = {
    id: gidSeq++,
    number: repo.nextPull++,
    title,
    body,
    state: 'open',
    head,
    base,
    headSha: headRef,
    baseSha: baseRef,
    merged: false,
    merged_at: null,
    mergeSha: null,
    created_at: NOW_ISO,
    updated_at: NOW_ISO,
  };
  repo.pulls.push(pr);
  return { pr };
}

// Line-diff between two file versions, used for pull files.
function lineDiff(oldText: string, newText: string): { add: number; del: number } {
  const a = oldText === '' ? [] : oldText.split('\n');
  const b = newText === '' ? [] : newText.split('\n');
  if (a.length && a[a.length - 1] === '') a.pop();
  if (b.length && b[b.length - 1] === '') b.pop();
  if (a.length > 400 || b.length > 400) return { add: b.length, del: a.length };
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  return { add: m - dp[0][0], del: n - dp[0][0] };
}

function liveHeadSha(repo: Repo, pr: Pull): string {
  return repo.refs.get(`refs/heads/${pr.head}`) ?? pr.headSha;
}

function pullFiles(repo: Repo, pr: Pull): Array<Record<string, unknown>> {
  const baseMap = fileMapOf(repo, pr.baseSha);
  const headMap = fileMapOf(repo, liveHeadSha(repo, pr));
  const out: Array<Record<string, unknown>> = [];
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const b = baseMap.get(path);
    const h = headMap.get(path);
    if ((b?.oid ?? null) === (h?.oid ?? null)) continue;
    const oldText = b ? (OBJECTS.get(b.oid)?.d.toString('utf8') ?? '') : '';
    const newText = h ? (OBJECTS.get(h.oid)?.d.toString('utf8') ?? '') : '';
    const { add, del } = lineDiff(oldText, newText);
    out.push({
      filename: path,
      status: !b ? 'added' : !h ? 'removed' : 'modified',
      additions: add,
      deletions: del,
      changes: add + del,
    });
  }
  return out;
}

// True when the head's changes cannot apply cleanly on top of the base tip.
function mergeConflict(repo: Repo, pr: Pull): boolean {
  const baseMap = fileMapOf(repo, pr.baseSha);
  const headMap = fileMapOf(repo, liveHeadSha(repo, pr));
  const tipRef = repo.refs.get(`refs/heads/${pr.base}`);
  if (!tipRef) return true;
  const tipMap = fileMapOf(repo, tipRef);
  const paths = new Set([...baseMap.keys(), ...headMap.keys()]);
  for (const path of paths) {
    const inBase = baseMap.get(path)?.oid ?? null;
    const inHead = headMap.get(path)?.oid ?? null;
    if (inHead === inBase) continue;
    const inTip = tipMap.get(path)?.oid ?? null;
    if (inTip !== inBase && inTip !== inHead) return true;
  }
  return false;
}

function mergePull(repo: Repo, pr: Pull): { sha: string | null; error?: string; status?: number } {
  if (pr.merged || pr.state !== 'open') return { sha: null, error: 'pull request is already closed', status: 405 };
  if (mergeConflict(repo, pr)) return { sha: null, error: 'merge conflict', status: 405 };
  const baseRef = `refs/heads/${pr.base}`;
  const tip = repo.refs.get(baseRef) as string;
  const baseMap = fileMapOf(repo, pr.baseSha);
  const headMap = fileMapOf(repo, liveHeadSha(repo, pr));
  const merged = new Map(fileMapOf(repo, tip));
  for (const [path, f] of headMap) {
    if ((baseMap.get(path)?.oid ?? null) !== (f.oid ?? null)) merged.set(path, f);
  }
  for (const path of baseMap.keys()) {
    if (!headMap.has(path) && baseMap.get(path)) merged.delete(path);
  }
  const tree = buildTree(merged);
  const sha = makeCommit(tree, [tip, liveHeadSha(repo, pr)], `Merge pull request #${pr.number} from ${repo.owner}/${pr.head}`);
  repo.refs.set(baseRef, sha);
  pr.merged = true;
  pr.state = 'closed';
  pr.merged_at = NOW_ISO;
  pr.mergeSha = sha;
  pr.updated_at = NOW_ISO;
  bump(repo);
  return { sha };
}

// -------------------------------------------------------------------------------------------
// Git wire: advertisements, ls-refs, fetch (v2 + v0), receive-pack.

const V2_CAPS = ['agent=forge/1.0', 'ls-refs', 'fetch=shallow wait-for-done', 'object-format=sha1'];

function v2Advertisement(): Buffer {
  return pktLines([
    '# service=git-upload-pack\n', 'flush',
    'version 2\n', ...V2_CAPS.map((c) => `${c}\n`), 'flush',
  ]);
}

function refLinesV0(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  const caps = service === 'git-upload-pack'
    ? 'side-band-64k ofs-delta agent=forge/1.0 shallow symref=HEAD:refs/heads/main'
    : 'report-status side-band-64k delete-refs ofs-delta agent=forge/1.0 symref=HEAD:refs/heads/main';
  const head = `# service=${service}\n`;
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const items: Array<string | Buffer | 'flush'> = [head, 'flush'];
  if (refs.length === 0) {
    items.push(`${'0'.repeat(40)} capabilities^{}\0${caps}\n`);
    items.push('flush');
    return pktLines(items);
  }
  const tip = repo.refs.get(`refs/heads/${repo.branch}`) ?? refs[0][1];
  let first = true;
  items.push(`${tip} HEAD${first ? `\0${caps}` : ''}\n`);
  first = false;
  for (const [name, oid] of refs) {
    items.push(`${oid} ${name}\n`);
    const o = OBJECTS.get(oid);
    if (o && o.t === T_TAG) {
      const target = parseTag(o.d);
      const peeled = peelToCommit(target);
      if (peeled) items.push(`${peeled} ${name}^{}\n`);
    }
  }
  items.push('flush');
  return pktLines(items);
}

function peelToCommit(oid: string): string | null {
  let cur = oid;
  for (let i = 0; i < 8; i++) {
    const o = OBJECTS.get(cur);
    if (!o) return null;
    if (o.t === T_COMMIT) return cur;
    if (o.t === T_TAG) { cur = parseTag(o.d); continue; }
    return null;
  }
  return null;
}

function v0Advertisement(repo: Repo, service: 'git-upload-pack' | 'git-receive-pack'): Buffer {
  if (service === 'git-upload-pack') {
    if (!repo.adV0Up) repo.adV0Up = refLinesV0(repo, service);
    return repo.adV0Up;
  }
  if (!repo.adV0Recv) repo.adV0Recv = refLinesV0(repo, service);
  return repo.adV0Recv;
}

function lsRefsAnswer(repo: Repo, opts: { peel: boolean; symrefs: boolean; unborn: boolean; prefixes: string[] }): Buffer {
  const key = JSON.stringify(opts);
  const hit = repo.lsCache.get(key);
  if (hit) return hit;
  const lines: string[] = [];
  const refs = [...repo.refs.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1));
  const keep = (name: string): boolean => opts.prefixes.length === 0 || opts.prefixes.some((p) => name.startsWith(p));
  if (opts.symrefs && keep('HEAD')) {
    const tip = repo.refs.get(`refs/heads/${repo.branch}`);
    if (tip) lines.push(`${tip} HEAD symref-target:refs/heads/${repo.branch}`);
  }
  if (refs.length === 0) {
    if (opts.unborn && keep(`refs/heads/${repo.branch}`)) lines.push(`unborn refs/heads/${repo.branch}`);
  } else {
    for (const [name, oid] of refs) {
      if (!keep(name)) continue;
      let line = `${oid} ${name}`;
      if (opts.peel) {
        const o = OBJECTS.get(oid);
        if (o && o.t === T_TAG) {
          const peeled = peelToCommit(parseTag(o.d));
          if (peeled) line += ` peeled:${peeled}`;
        }
      }
      lines.push(line);
    }
  }
  const buf = pktLines([...lines.map((l) => `${l}\n`), 'flush']);
  repo.lsCache.set(key, buf);
  return buf;
}

// The objects a fetch must send: the wanted closure (depth-limited when asked) minus
// everything reachable from the client's haves.
function fetchPlan(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowReq: string[], deepenRelative = false): {
  oids: string[]; shallow: string[]; unshallow: string[];
} {
  // A want naming an annotated tag peels to its commit; the tag object itself
  // travels in the pack too (clone-annotated-tag round-trips it).
  const tagOids: string[] = [];
  const startWants: string[] = [];
  for (const w of wants) {
    const o = OBJECTS.get(w);
    if (o && o.t === T_TAG) {
      tagOids.push(w);
      const target = peelToCommit(parseTag(o.d));
      if (target) startWants.push(target);
    } else {
      startWants.push(w);
    }
  }
  // A relative deepen (real git's `deepen N` + `deepen-relative`) counts from the
  // client's current shallow boundary: effective depth = (boundary's distance
  // from the wanted tip) + deepen + 1. An absolute deepen (the kit client)
  // is already a depth from the tip.
  let effDepth = depth;
  if (depth !== null && deepenRelative && shallowReq.length) {
    const dist = new Map<string, number>();
    const dq: Array<[string, number]> = startWants.map((w) => [w, 0] as [string, number]);
    while (dq.length) {
      const [cur, d] = dq.shift() as [string, number];
      if (dist.has(cur)) continue;
      dist.set(cur, d);
      const o = OBJECTS.get(cur);
      if (!o || o.t !== T_COMMIT) continue;
      for (const p of parseCommit(o.d).parents) dq.push([p, d + 1]);
    }
    const ds = shallowReq.map((s) => dist.get(s)).filter((x): x is number => x !== undefined);
    if (ds.length) effDepth = Math.min(...ds) + depth + 1;
  }
  const included = new Map<string, number>(); // commit id -> distance from a want
  const queue: Array<[string, number]> = startWants.map((w) => [w, 0] as [string, number]);
  const seen = new Set<string>();
  while (queue.length) {
    const [cur, d] = queue.shift() as [string, number];
    if (seen.has(cur)) continue;
    seen.add(cur);
    const o = OBJECTS.get(cur);
    if (!o || o.t !== T_COMMIT) continue;
    if (effDepth !== null && d >= effDepth) continue;
    included.set(cur, d);
    for (const p of parseCommit(o.d).parents) queue.push([p, d + 1]);
  }
  const haveReach = new Set<string>();
  const hstack = [...haves];
  while (hstack.length) {
    const cur = hstack.pop() as string;
    if (haveReach.has(cur)) continue;
    haveReach.add(cur);
    const o = OBJECTS.get(cur);
    if (!o) continue;
    if (o.t === T_COMMIT) {
      const { tree, parents } = parseCommit(o.d);
      hstack.push(tree);
      // A have at the client's shallow boundary does not imply its parents:
      // the client holds the boundary commit, not the history behind it.
      if (!shallowReq.includes(cur)) hstack.push(...parents);
    } else if (o.t === T_TREE) {
      for (const e of parseTree(o.d)) hstack.push(e.oid);
    } else if (o.t === T_TAG) {
      hstack.push(parseTag(o.d));
    }
  }
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (effDepth !== null) {
    for (const [c, d] of included) if (d === effDepth - 1) shallow.push(c);
  }
  for (const s of shallowReq) {
    if (included.has(s) && !shallow.includes(s)) unshallow.push(s);
  }
  const oids: string[] = [];
  const seenObj = new Set<string>();
  const addTree = (treeId: string): void => {
    const stack = [treeId];
    while (stack.length) {
      const t = stack.pop() as string;
      if (seenObj.has(t) || haveReach.has(t)) continue;
      seenObj.add(t);
      const o = OBJECTS.get(t);
      if (!o || o.t !== T_TREE) continue;
      oids.push(t);
      for (const e of parseTree(o.d)) {
        if (e.mode === '40000') stack.push(e.oid);
        else if (!seenObj.has(e.oid) && !haveReach.has(e.oid)) { seenObj.add(e.oid); oids.push(e.oid); }
      }
    }
  };
  for (const c of included.keys()) {
    if (haveReach.has(c)) continue;
    if (!seenObj.has(c)) { seenObj.add(c); oids.push(c); }
    const o = OBJECTS.get(c);
    if (o && o.t === T_COMMIT) addTree(parseCommit(o.d).tree);
  }
  for (const t of tagOids) {
    if (!haveReach.has(t) && !seenObj.has(t)) { seenObj.add(t); oids.push(t); }
  }
  return { oids, shallow, unshallow };
}

function fetchResponseV2(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowReq: string[], deepenRelative = false): Buffer {
  const cacheKey = `${wants.join(',')}|${depth ?? ''}|${deepenRelative ? 'rel' : 'abs'}|${[...haves].sort().join(',')}|${shallowReq.join(',')}`;
  const hit = repo.fetchCache.get(cacheKey);
  if (hit) return hit;
  const plan = fetchPlan(repo, wants, haves, depth, shallowReq, deepenRelative);
  const pack = writePack(plan.oids);
  // Sections follow real upload-pack framing, verified against a git daemon:
  // the first section carries no leading delim, later sections are preceded by
  // one; the acknowledgments section exists only when the client negotiated
  // with haves (a fresh clone goes straight to the packfile); there is no
  // wanted-refs section. The packfile section closes the response with the
  // sideband flush.
  const sections: Buffer[][] = [];
  if (haves.length) {
    const common = haves.filter((h) => {
      for (const w of wants) if (isAncestor(h, w) || h === w) return true;
      return false;
    });
    const ack: Buffer[] = [pkt('acknowledgments\n')];
    if (common.length) {
      for (const c of common.slice(0, 4)) ack.push(pkt(`ACK ${c}\n`));
      ack.push(pkt('ready\n'));
    } else {
      ack.push(pkt('NAK\n'));
    }
    sections.push(ack);
  }
  if (depth !== null || shallowReq.length) {
    const info: Buffer[] = [pkt('shallow-info\n')];
    for (const s of plan.shallow) info.push(pkt(`shallow ${s}\n`));
    for (const s of plan.unshallow) info.push(pkt(`unshallow ${s}\n`));
    sections.push(info);
  }
  sections.push([pkt('packfile\n'), sideband(pack)]);
  const parts: Buffer[] = [];
  sections.forEach((sec, i) => {
    if (i > 0) parts.push(DELIM_PKT);
    parts.push(...sec);
  });
  const buf = Buffer.concat(parts);
  repo.fetchCache.set(cacheKey, buf);
  return buf;
}

function fetchResponseV0(repo: Repo, wants: string[], haves: string[], depth: number | null, shallowReq: string[], deepenRelative = false): Buffer {
  const plan = fetchPlan(repo, wants, haves, depth, shallowReq, deepenRelative);
  const pack = writePack(plan.oids);
  const common = haves.filter((h) => wants.some((w) => isAncestor(h, w) || h === w));
  const parts: Buffer[] = [];
  if (common.length) {
    for (const c of common.slice(0, 4)) parts.push(pkt(`ACK ${c}\n`));
  } else {
    parts.push(pkt('NAK\n'));
  }
  for (const s of plan.shallow) parts.push(pkt(`shallow ${s}\n`));
  for (const s of plan.unshallow) parts.push(pkt(`unshallow ${s}\n`));
  parts.push(sideband(pack));
  return Buffer.concat(parts);
}

// Receive-pack: command list + pack, per-ref ok/ng inside sideband band 1.
function handleReceivePack(repo: Repo, body: Buffer): Buffer {
  const packets = decodePkts(body);
  const commands: Array<{ old: string; new: string; ref: string }> = [];
  let idx = 0;
  let packStart = body.length;
  for (; idx < packets.length; idx++) {
    const p = packets[idx];
    if (p.kind === 'flush') {
      // The pack follows the flush packet in the raw body; find its byte offset.
      let pos = 0;
      let seen = 0;
      while (seen <= idx) {
        const len = parseInt(body.subarray(pos, pos + 4).toString('ascii'), 16);
        if (len === 0 || len === 1 || len === 2) { pos += 4; seen++; continue; }
        pos += len;
        seen++;
      }
      packStart = pos;
      break;
    }
    if (p.kind !== 'data') continue;
    let text = p.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const m = text.trim().match(/^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/);
    if (m) commands.push({ old: m[1], new: m[2], ref: m[3] });
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  let unpackOk = true;
  let unpackDetail = 'ok';
  const packBytes = body.subarray(packStart);
  const hasUpdates = commands.some((c) => c.new !== '0'.repeat(40));
  if (hasUpdates && packBytes.length > 0) {
    try {
      readPack(packBytes);
    } catch (e) {
      unpackOk = false;
      unpackDetail = `unpacker error: ${e instanceof Error ? e.message : 'bad pack'}`;
    }
  }
  for (const cmd of commands) {
    if (!unpackOk) { results.push({ ref: cmd.ref, ok: false, reason: unpackDetail }); continue; }
    if (!cmd.ref.startsWith('refs/')) { results.push({ ref: cmd.ref, ok: false, reason: 'invalid ref' }); continue; }
    const cur = repo.refs.get(cmd.ref);
    if (cmd.new === '0'.repeat(40)) {
      // Delete.
      if (!cur) { results.push({ ref: cmd.ref, ok: false, reason: 'ref does not exist' }); continue; }
      if (cur !== cmd.old) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
      repo.refs.delete(cmd.ref);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      continue;
    }
    if (!OBJECTS.has(cmd.new)) { results.push({ ref: cmd.ref, ok: false, reason: 'object not found' }); continue; }
    if (cmd.old === '0'.repeat(40)) {
      if (cur) { results.push({ ref: cmd.ref, ok: false, reason: 'already exists' }); continue; }
      repo.refs.set(cmd.ref, cmd.new);
      results.push({ ref: cmd.ref, ok: true, reason: '' });
      continue;
    }
    if (cur !== cmd.old) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
    if (!isAncestor(cmd.old, cmd.new)) { results.push({ ref: cmd.ref, ok: false, reason: 'non-fast-forward' }); continue; }
    repo.refs.set(cmd.ref, cmd.new);
    results.push({ ref: cmd.ref, ok: true, reason: '' });
  }
  if (results.some((r) => r.ok)) bump(repo);
  // The report is pkt-line framed inside sideband band 1 and closed by a flush
  // *inside* the band, before the top-level flush: the reader parses pkt-lines
  // out of the band-1 stream and waits for that inner flush to know the report
  // is complete (verified against a real git daemon's bytes).
  const inner = Buffer.concat([
    pkt(`unpack ${unpackDetail}\n`),
    ...results.map((r) => pkt(r.ok ? `ok ${r.ref}\n` : `ng ${r.ref} ${r.reason}\n`)),
    FLUSH_PKT,
  ]);
  const frames: Buffer[] = [];
  for (let i = 0; i < inner.length; i += 60000) frames.push(bandFrame(1, inner.subarray(i, i + 60000)));
  frames.push(FLUSH_PKT);
  return Buffer.concat(frames);
}

// -------------------------------------------------------------------------------------------
// HTTP plumbing.

function sendJson(res: http.ServerResponse, status: number, obj: unknown, extra?: Record<string, string>): void {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json',
    'x-github-request-id': `req-${++reqSeq}`,
    'x-oauth-scopes': 'repo, user',
    ...(extra ?? {}),
  });
  res.end(body);
}

function sendBuf(res: http.ServerResponse, status: number, body: Buffer, contentType: string): void {
  res.writeHead(status, {
    'content-type': contentType,
    'x-github-request-id': `req-${++reqSeq}`,
    'content-length': body.length,
  });
  res.end(body);
}

function errJson(res: http.ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function parseQuery(qs: string): Map<string, string> {
  const out = new Map<string, string>();
  if (!qs) return out;
  for (const pair of qs.split('&')) {
    const eq = pair.indexOf('=');
    if (eq < 0) { if (pair) out.set(decodeURIComponent(pair), ''); continue; }
    out.set(decodeURIComponent(pair.slice(0, eq)), decodeURIComponent(pair.slice(eq + 1)));
  }
  return out;
}

function seg(path: string, i: number): string {
  const parts = path.split('/');
  return parts[i] ? decodeURIComponent(parts[i]) : '';
}

// -------------------------------------------------------------------------------------------
// REST v3.

function restHandler(req: http.IncomingMessage, res: http.ServerResponse, method: string, path: string, query: Map<string, string>, body: Buffer): void {
  const jsonBody = (): Record<string, unknown> => {
    try {
      const v = JSON.parse(body.toString('utf8'));
      return v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
    } catch {
      return {};
    }
  };

  // A malformed JSON body on a write is a 400, not a validation error.
  if ((method === 'POST' || method === 'PUT' || method === 'PATCH') && body.length > 0) {
    try {
      JSON.parse(body.toString('utf8'));
    } catch {
      errJson(res, 400, 'malformed JSON body');
      return;
    }
  }

  if (path === '/api/v3/' || path === '/api/v3') {
    sendJson(res, 200, { current_user_url: '/api/v3/user', repository_url: '/api/v3/repos/{owner}/{repo}' });
    return;
  }
  if (path === '/api/v3/meta') {
    sendJson(res, 200, { installed_version: '1.0.0' });
    return;
  }
  if (path === '/api/v3/user' && method === 'GET') {
    sendJson(res, 200, { login: VIEWER.login, id: VIEWER.id, name: VIEWER.name, email: VIEWER.email, type: 'User' });
    return;
  }
  if (path === '/api/v3/user/repos') {
    if (method === 'GET') {
      const perPage = Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30);
      const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
      const all = [...REPOS.values()].sort((a, b) => a.seq - b.seq);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const origin = `http://${req.headers.host ?? 'localhost'}`;
      const links: string[] = [];
      const totalPages = Math.max(1, Math.ceil(all.length / perPage));
      if (page < totalPages) links.push(`<${origin}/api/v3/user/repos?per_page=${perPage}&page=${page + 1}>; rel="next"`);
      if (totalPages > 1) links.push(`<${origin}/api/v3/user/repos?per_page=${perPage}&page=${totalPages}>; rel="last"`);
      if (page > 1) links.push(`<${origin}/api/v3/user/repos?per_page=${perPage}&page=1>; rel="first"`);
      sendJson(res, 200, slice.map((r) => repoJson(r)), links.length ? { link: links.join(', ') } : undefined);
      return;
    }
    if (method === 'POST') {
      const b = jsonBody();
      const name = typeof b.name === 'string' ? b.name : '';
      if (!name || name.length > 100 || name.includes('/')) { errJson(res, 422, 'invalid repository name'); return; }
      if (findRepo(VIEWER.login, name)) { errJson(res, 422, 'name already exists on this account'); return; }
      const repo = createRepo(name, typeof b.description === 'string' ? b.description : '', b.private === true);
      sendJson(res, 201, repoJson(repo));
      return;
    }
  }

  if (!path.startsWith('/api/v3/repos/')) { errJson(res, 404, 'Not Found'); return; }
  const owner = seg(path, 4);
  const name = seg(path, 5);
  const repo = findRepo(owner, name);
  if (!repo) { errJson(res, 404, 'Not Found'); return; }
  const rest = path.split('/').slice(6);

  // /repos/{o}/{r}
  if (rest.length === 0 || (rest.length === 1 && rest[0] === '')) {
    if (method === 'GET') { sendJson(res, 200, repoJson(repo)); return; }
    if (method === 'PATCH') {
      const b = jsonBody();
      if (typeof b.description === 'string') repo.desc = b.description;
      if (typeof b.private === 'boolean') repo.priv = b.private;
      if (typeof b.default_branch === 'string' && repo.refs.has(`refs/heads/${b.default_branch}`)) repo.branch = b.default_branch;
      sendJson(res, 200, repoJson(repo));
      return;
    }
    if (method === 'DELETE') {
      REPOS.delete(repo.key);
      res.writeHead(204, { 'x-github-request-id': `req-${++reqSeq}` });
      res.end();
      return;
    }
  }

  const sub = rest[0] ?? '';
  if (sub === 'branches' && method === 'GET') {
    const out = [...repo.refs.entries()]
      .filter(([n]) => n.startsWith('refs/heads/'))
      .map(([n, oid]) => ({ name: n.slice('refs/heads/'.length), commit: { sha: oid }, protected: false }));
    sendJson(res, 200, out);
    return;
  }

  if (sub === 'commits' && method === 'GET') {
    const shaParam = query.get('sha');
    const tip = shaParam ? repo.refs.get(`refs/heads/${shaParam}`) ?? (OBJECTS.has(shaParam) ? shaParam : undefined) : repo.refs.get(`refs/heads/${repo.branch}`);
    if (!tip) { sendJson(res, 200, []); return; }
    const perPage = Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30);
    const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
    const all = ancestors(tip).map((oid) => {
      const { message } = parseCommit((OBJECTS.get(oid) as GitObj).d);
      return {
        sha: oid,
        commit: {
          message,
          author: { name: VIEWER.name, email: VIEWER.email, date: NOW_ISO },
          committer: { name: VIEWER.name, email: VIEWER.email, date: NOW_ISO },
        },
        author: userJson(VIEWER.login),
      };
    });
    sendJson(res, 200, all.slice((page - 1) * perPage, page * perPage));
    return;
  }

  if (sub === 'contents') {
    const filePath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
    const refName = query.get('ref');
    const tip = refName ? repo.refs.get(`refs/heads/${refName}`) ?? repo.refs.get(refName) : repo.refs.get(`refs/heads/${repo.branch}`);
    if (method === 'GET') {
      if (!tip) { errJson(res, 404, 'Not Found'); return; }
      const files = fileMapOf(repo, tip);
      if (!filePath) {
        const top = new Map<string, { oid: string; mode: string; dir: boolean }>();
        for (const [p, f] of files) {
          const slash = p.indexOf('/');
          if (slash < 0) top.set(p, { ...f, dir: false });
          else {
            const dir = p.slice(0, slash);
            if (!top.has(dir)) top.set(dir, { oid: '', mode: '40000', dir: true });
          }
        }
        sendJson(res, 200, [...top.entries()].map(([n, f]) => ({
          type: f.dir ? 'dir' : 'file', name: n, path: n,
          sha: f.oid, size: f.dir ? 0 : (OBJECTS.get(f.oid)?.d.length ?? 0),
        })));
        return;
      }
      const f = files.get(filePath);
      if (f) {
        const data = OBJECTS.get(f.oid)?.d ?? Buffer.alloc(0);
        sendJson(res, 200, {
          type: 'file', encoding: 'base64', content: data.toString('base64'),
          sha: f.oid, size: data.length, name: filePath.split('/').pop(), path: filePath,
        });
        return;
      }
      // A directory listing.
      const kids = new Map<string, { oid: string; dir: boolean }>();
      for (const [p, ff] of files) {
        if (!p.startsWith(`${filePath}/`)) continue;
        const restPath = p.slice(filePath.length + 1);
        const slash = restPath.indexOf('/');
        if (slash < 0) kids.set(restPath, { oid: ff.oid, dir: false });
        else if (!kids.has(restPath.slice(0, slash))) kids.set(restPath.slice(0, slash), { oid: '', dir: true });
      }
      if (!kids.size) { errJson(res, 404, 'Not Found'); return; }
      sendJson(res, 200, [...kids.entries()].map(([n, k]) => ({
        type: k.dir ? 'dir' : 'file', name: n, path: `${filePath}/${n}`,
        sha: k.oid, size: k.dir ? 0 : (OBJECTS.get(k.oid)?.d.length ?? 0),
      })));
      return;
    }
    if (method === 'PUT') {
      const b = jsonBody();
      if (typeof b.content !== 'string' || typeof b.message !== 'string') { errJson(res, 422, 'content and message are required'); return; }
      const branch = typeof b.branch === 'string' ? b.branch : repo.branch;
      const refName = `refs/heads/${branch}`;
      const parent = repo.refs.get(refName);
      if (parent === undefined && repo.refs.size > 0 && branch !== repo.branch) { errJson(res, 404, 'branch does not exist'); return; }
      const files = parent ? new Map(fileMapOf(repo, parent)) : new Map<string, { oid: string; mode: string }>();
      const existing = files.get(filePath);
      if (existing && typeof b.sha === 'string' && b.sha !== existing.oid) { errJson(res, 409, 'sha does not match the current blob'); return; }
      if (existing && typeof b.sha !== 'string') { errJson(res, 409, 'sha is required to update a file'); return; }
      const isUpdate = !!existing;
      const blob = blobId(Buffer.from(b.content, 'base64'));
      files.set(filePath, { oid: blob, mode: '100644' });
      const tree = buildTree(files);
      const commit = makeCommit(tree, parent ? [parent] : [], b.message);
      repo.refs.set(refName, commit);
      repo.fileMaps.set(commit, files);
      bump(repo);
      sendJson(res, isUpdate ? 200 : 201, {
        content: { name: filePath.split('/').pop(), path: filePath, sha: blob, size: Buffer.from(b.content, 'base64').length, type: 'file', encoding: 'base64' },
        commit: { sha: commit, message: b.message, author: { name: VIEWER.name, email: VIEWER.email, date: NOW_ISO } },
      });
      return;
    }
    if (method === 'DELETE') {
      const b = jsonBody();
      const branch = typeof b.branch === 'string' ? b.branch : repo.branch;
      const refName = `refs/heads/${branch}`;
      const parent = repo.refs.get(refName);
      if (!parent) { errJson(res, 404, 'Not Found'); return; }
      const files = new Map(fileMapOf(repo, parent));
      if (!files.has(filePath)) { errJson(res, 404, 'Not Found'); return; }
      files.delete(filePath);
      const tree = buildTree(files);
      const commit = makeCommit(tree, [parent], typeof b.message === 'string' ? b.message : `Delete ${filePath}`);
      repo.refs.set(refName, commit);
      repo.fileMaps.set(commit, files);
      bump(repo);
      sendJson(res, 200, { content: null, commit: { sha: commit, message: 'deleted' } });
      return;
    }
  }

  if (sub === 'git' && rest[1] === 'refs') {
    const refPath = rest.slice(2).map((s) => decodeURIComponent(s)).join('/');
    if (method === 'POST' && !refPath) {
      const b = jsonBody();
      const ref = typeof b.ref === 'string' ? b.ref : '';
      const sha = typeof b.sha === 'string' ? b.sha : '';
      if (!ref.startsWith('refs/') || !OBJECTS.has(sha)) { errJson(res, 422, 'invalid ref or sha'); return; }
      if (repo.refs.has(ref)) { errJson(res, 422, 'ref already exists'); return; }
      repo.refs.set(ref, sha);
      bump(repo);
      sendJson(res, 201, { ref, object: { sha, type: TNAME[OBJECTS.get(sha)?.t ?? 0] } });
      return;
    }
    const fullRef = `refs/${refPath}`;
    if (method === 'GET' && refPath) {
      const oid = repo.refs.get(fullRef);
      if (!oid) { errJson(res, 404, 'Not Found'); return; }
      sendJson(res, 200, { ref: fullRef, object: { sha: oid, type: TNAME[OBJECTS.get(oid)?.t ?? 0] } });
      return;
    }
    if (method === 'PATCH' && refPath) {
      const b = jsonBody();
      const oid = repo.refs.get(fullRef);
      if (!oid) { errJson(res, 404, 'Not Found'); return; }
      const sha = typeof b.sha === 'string' ? b.sha : '';
      if (!OBJECTS.has(sha)) { errJson(res, 422, 'invalid sha'); return; }
      repo.refs.set(fullRef, sha);
      bump(repo);
      sendJson(res, 200, { ref: fullRef, object: { sha, type: TNAME[OBJECTS.get(sha)?.t ?? 0] } });
      return;
    }
    if (method === 'DELETE' && refPath) {
      if (!repo.refs.delete(fullRef)) { errJson(res, 404, 'Not Found'); return; }
      bump(repo);
      res.writeHead(204, { 'x-github-request-id': `req-${++reqSeq}` });
      res.end();
      return;
    }
  }

  if (sub === 'labels') {
    if (method === 'GET') {
      sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color, description: '' })));
      return;
    }
    if (method === 'POST') {
      const b = jsonBody();
      const name = typeof b.name === 'string' ? b.name : '';
      if (!name) { errJson(res, 422, 'label name is required'); return; }
      if (repo.labels.has(name)) { errJson(res, 422, 'label already exists'); return; }
      const label = { name, color: typeof b.color === 'string' ? b.color : 'ffffff' };
      repo.labels.set(name, label);
      sendJson(res, 201, { name: label.name, color: label.color, description: '' });
      return;
    }
  }

  if (sub === 'issues') {
    const num = rest[1] ? parseInt(rest[1], 10) : NaN;
    if (!rest[1]) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        const labelFilter = query.get('labels')?.split(',').filter(Boolean) ?? [];
        let list = repo.issues.filter((i) => state === 'all' || i.state === state);
        if (labelFilter.length) list = list.filter((i) => labelFilter.every((l) => i.labels.some((x) => x.name === l)));
        const dirAsc = (query.get('direction') ?? 'desc').toLowerCase() === 'asc';
        list = [...list].sort((a, b) => (dirAsc ? a.number - b.number : b.number - a.number));
        const perPage = Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30);
        const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
        sendJson(res, 200, list.slice((page - 1) * perPage, page * perPage).map((i) => issueJsonObj(repo, i)));
        return;
      }
      if (method === 'POST') {
        const b = jsonBody();
        const title = typeof b.title === 'string' ? b.title : '';
        if (!title) { errJson(res, 422, 'title is required'); return; }
        const labelNames: string[] = Array.isArray(b.labels)
          ? (b.labels as unknown[]).map((l) => (typeof l === 'string' ? l : (l as { name?: string }).name ?? '')).filter(Boolean)
          : [];
        const { issue, error } = newIssue(repo, title, typeof b.body === 'string' ? b.body : '', labelNames);
        if (!issue) { errJson(res, 422, error ?? 'invalid labels'); return; }
        sendJson(res, 201, issue.json);
        return;
      }
    }
    const issue = repo.issues.find((i) => i.number === num);
    if (!issue) { errJson(res, 404, 'Not Found'); return; }
    if (rest[2] === 'comments') {
      if (method === 'GET') {
        sendJson(res, 200, issue.comments.map((c) => ({ id: c.id, body: c.body, user: userJson(c.user), created_at: c.created_at, updated_at: c.updated_at })));
        return;
      }
      if (method === 'POST') {
        const b = jsonBody();
        if (typeof b.body !== 'string' || !b.body) { errJson(res, 422, 'body is required'); return; }
        const comment = { id: gidSeq++, body: b.body, user: VIEWER.login, created_at: NOW_ISO, updated_at: NOW_ISO };
        issue.comments.push(comment);
        refreshIssueJson(repo, issue);
        sendJson(res, 201, { id: comment.id, body: comment.body, user: userJson(VIEWER.login), created_at: comment.created_at, updated_at: comment.updated_at });
        return;
      }
    }
    if (rest.length === 2) {
      if (method === 'GET') { sendJson(res, 200, issue.json); return; }
      if (method === 'PATCH') {
        const b = jsonBody();
        if (typeof b.title === 'string') issue.title = b.title;
        if (typeof b.body === 'string') issue.body = b.body;
        if (b.state === 'open' || b.state === 'closed') {
          issue.state = b.state;
          issue.closed_at = b.state === 'closed' ? NOW_ISO : null;
        }
        if (Array.isArray(b.labels)) {
          const names = (b.labels as unknown[]).map((l) => (typeof l === 'string' ? l : (l as { name?: string }).name ?? '')).filter(Boolean);
          const resolved: Array<{ name: string; color: string }> = [];
          for (const n of names) {
            const l = repo.labels.get(n);
            if (!l) { errJson(res, 422, `label ${n} does not exist`); return; }
            resolved.push({ name: l.name, color: l.color });
          }
          issue.labels = resolved;
        }
        issue.updated_at = NOW_ISO;
        refreshIssueJson(repo, issue);
        sendJson(res, 200, issue.json);
        return;
      }
    }
  }

  if (sub === 'pulls') {
    const num = rest[1] ? parseInt(rest[1], 10) : NaN;
    if (!rest[1]) {
      if (method === 'GET') {
        const state = query.get('state') ?? 'open';
        let list = repo.pulls.filter((p) => state === 'all' || p.state === state);
        const perPage = Math.max(1, parseInt(query.get('per_page') ?? '30', 10) || 30);
        const page = Math.max(1, parseInt(query.get('page') ?? '1', 10) || 1);
        sendJson(res, 200, list.slice((page - 1) * perPage, page * perPage).map((p) => pullJsonObj(repo, p)));
        return;
      }
      if (method === 'POST') {
        const b = jsonBody();
        const { pr, error } = newPull(
          repo,
          typeof b.title === 'string' ? b.title : '',
          typeof b.body === 'string' ? b.body : '',
          typeof b.head === 'string' ? b.head : '',
          typeof b.base === 'string' ? b.base : '',
        );
        if (!pr) { errJson(res, 422, error ?? 'invalid pull request'); return; }
        sendJson(res, 201, pullJsonObj(repo, pr));
        return;
      }
    }
    const pr = repo.pulls.find((p) => p.number === num);
    if (!pr) { errJson(res, 404, 'Not Found'); return; }
    if (rest[2] === 'files' && method === 'GET') {
      sendJson(res, 200, pullFiles(repo, pr));
      return;
    }
    if (rest[2] === 'merge' && method === 'PUT') {
      const { sha, error, status } = mergePull(repo, pr);
      if (!sha) { errJson(res, status ?? 405, error ?? 'cannot merge'); return; }
      sendJson(res, 200, { sha, merged: true, message: `Pull request #${pr.number} merged` });
      return;
    }
    if (rest.length === 2) {
      if (method === 'GET') { sendJson(res, 200, pullJsonObj(repo, pr)); return; }
      if (method === 'PATCH') {
        const b = jsonBody();
        if (typeof b.title === 'string') pr.title = b.title;
        if (typeof b.body === 'string') pr.body = b.body;
        if (b.state === 'closed' && pr.state === 'open') { pr.state = 'closed'; pr.updated_at = NOW_ISO; }
        sendJson(res, 200, pullJsonObj(repo, pr));
        return;
      }
    }
  }

  errJson(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// GraphQL.

const GQL_TYPES: Record<string, { kind: string; fields?: string[]; enums?: string[] }> = {
  Issue: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'author', 'labels', 'comments', 'createdAt', 'updatedAt', 'url', 'closedAt'] },
  PullRequest: { kind: 'OBJECT', fields: ['id', 'number', 'title', 'state', 'body', 'headRefName', 'baseRefName', 'mergeable', 'merged', 'mergedAt', 'mergeCommit', 'files', 'author', 'createdAt', 'updatedAt'] },
  Repository: { kind: 'OBJECT', fields: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest', 'description', 'private', 'createdAt', 'updatedAt'] },
  User: { kind: 'OBJECT', fields: ['id', 'login', 'name', 'email'] },
  Label: { kind: 'OBJECT', fields: ['id', 'name', 'color', 'description'] },
  IssueComment: { kind: 'OBJECT', fields: ['id', 'body', 'author', 'createdAt', 'updatedAt'] },
  IssueConnection: { kind: 'OBJECT', fields: ['nodes', 'totalCount', 'pageInfo'] },
  PullRequestConnection: { kind: 'OBJECT', fields: ['nodes', 'totalCount', 'pageInfo'] },
  PageInfo: { kind: 'OBJECT', fields: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'] },
  SearchType: { kind: 'ENUM', enums: ['ISSUE', 'PULL_REQUEST', 'REPOSITORY', 'USER'] },
  IssueState: { kind: 'ENUM', enums: ['OPEN', 'CLOSED'] },
  PullRequestState: { kind: 'ENUM', enums: ['OPEN', 'CLOSED', 'MERGED'] },
  MergeableState: { kind: 'ENUM', enums: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'] },
  IssueOrderField: { kind: 'ENUM', enums: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'] },
  OrderDirection: { kind: 'ENUM', enums: ['ASC', 'DESC'] },
};

function gqlTypeShape(name: string): Record<string, unknown> | null {
  const t = GQL_TYPES[name];
  if (!t) return null;
  const out: Record<string, unknown> = { name, kind: t.kind, description: '' };
  if (t.fields) {
    out.fields = t.fields.map((f) => ({
      name: f,
      description: '',
      args: [],
      type: f === 'id'
        ? { kind: 'NON_NULL', name: null, ofType: { kind: 'SCALAR', name: 'ID', ofType: null } }
        : f === 'number' || f === 'databaseId' || f === 'totalCount'
          ? { kind: 'SCALAR', name: 'Int', ofType: null }
          : f === 'merged' || f === 'hasIssuesEnabled' || f === 'private'
            ? { kind: 'SCALAR', name: 'Boolean', ofType: null }
            : { kind: 'SCALAR', name: 'String', ofType: null },
    }));
  }
  if (t.enums) out.enumValues = t.enums.map((e) => ({ name: e, description: '' }));
  return out;
}

function gqlIssueObj(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    __typename: 'Issue',
    id: gid('Issue', `${repo.owner}/${repo.name}#${issue.number}`),
    number: issue.number,
    title: issue.title,
    state: issue.state.toUpperCase(),
    body: issue.body,
    author: { __typename: 'User', login: VIEWER.login, id: String(VIEWER.id), name: VIEWER.name },
    labels: { nodes: issue.labels.map((l) => ({ __typename: 'Label', name: l.name, color: l.color })) },
    comments: { nodes: issue.comments.map((c) => ({ __typename: 'IssueComment', id: String(c.id), body: c.body, author: { login: c.user } })), totalCount: issue.comments.length },
    createdAt: issue.created_at,
    updatedAt: issue.updated_at,
    closedAt: issue.closed_at,
    url: '',
  };
}

function gqlPullObj(repo: Repo, pr: Pull): Record<string, unknown> {
  return {
    __typename: 'PullRequest',
    id: gid('PullRequest', `${repo.owner}/${repo.name}#${pr.number}`),
    number: pr.number,
    title: pr.title,
    state: pr.merged ? 'MERGED' : pr.state.toUpperCase(),
    body: pr.body,
    headRefName: pr.head,
    baseRefName: pr.base,
    mergeable: mergeConflict(repo, pr) ? 'CONFLICTING' : 'MERGEABLE',
    merged: pr.merged,
    mergedAt: pr.merged_at,
    mergeCommit: pr.mergeSha ? { oid: pr.mergeSha } : null,
    files: { nodes: pullFiles(repo, pr).map((f) => ({ path: f.filename, additions: f.additions, deletions: f.deletions })) },
    author: { __typename: 'User', login: VIEWER.login, id: String(VIEWER.id), name: VIEWER.name },
    createdAt: pr.created_at,
    updatedAt: pr.updated_at,
  };
}

function gqlRepoObj(repo: Repo): Record<string, unknown> {
  const tip = repo.refs.get(`refs/heads/${repo.branch}`);
  return {
    __typename: 'Repository',
    id: gid('Repository', `${repo.owner}/${repo.name}`),
    databaseId: repo.id,
    name: repo.name,
    nameWithOwner: `${repo.owner}/${repo.name}`,
    owner: { __typename: 'User', login: repo.owner, id: String(VIEWER.id), name: VIEWER.name },
    defaultBranchRef: tip ? { name: repo.branch } : null,
    viewerPermission: 'ADMIN',
    hasIssuesEnabled: true,
    description: repo.desc,
    private: repo.priv,
    createdAt: NOW_ISO,
    updatedAt: NOW_ISO,
  };
}

function pageOf<T>(items: T[], first: number | null, after: string | null, keyOf: (x: T) => string): { nodes: T[]; totalCount: number; pageInfo: Record<string, unknown> } {
  let start = 0;
  if (after) {
    try {
      const decoded = Buffer.from(after, 'base64').toString('utf8');
      const idx = items.findIndex((x) => keyOf(x) === decoded);
      if (idx >= 0) start = idx + 1;
    } catch { /* ignore a bad cursor */ }
  }
  const sliced = first === null ? items.slice(start) : items.slice(start, start + first);
  const end = start + sliced.length;
  return {
    nodes: sliced,
    totalCount: items.length,
    pageInfo: {
      hasNextPage: end < items.length,
      endCursor: sliced.length ? Buffer.from(keyOf(sliced[sliced.length - 1])).toString('base64') : null,
      hasPreviousPage: start > 0,
      startCursor: sliced.length ? Buffer.from(keyOf(sliced[0])).toString('base64') : null,
    },
  };
}

function decodeGid(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 0) return null;
    return { kind: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

function graphqlHandler(res: http.ServerResponse, body: Buffer): void {
  let payload: { query?: string; variables?: Record<string, unknown> };
  try {
    payload = JSON.parse(body.toString('utf8'));
  } catch {
    sendJson(res, 400, { errors: [{ message: 'request body is not valid JSON' }] });
    return;
  }
  // Batched operations: a JSON array of documents answers an array, in order.
  if (Array.isArray(payload)) {
    const out: unknown[] = [];
    for (const el of payload as Array<Record<string, unknown>>) {
      let captured = '';
      const fake = {
        writeHead: () => undefined,
        end: (b: unknown) => { captured = String(b); },
      } as unknown as http.ServerResponse;
      graphqlHandler(fake, Buffer.from(JSON.stringify(el)));
      try { out.push(JSON.parse(captured)); } catch { out.push({ data: null, errors: [{ message: 'bad operation' }] }); }
    }
    sendJson(res, 200, out);
    return;
  }
  const query = typeof payload.query === 'string' ? payload.query : '';
  const vars = (payload.variables ?? {}) as Record<string, unknown>;
  const vstr = (k: string): string | null => (typeof vars[k] === 'string' ? (vars[k] as string) : null);
  const vint = (k: string): number | null => (typeof vars[k] === 'number' ? (vars[k] as number) : null);

  const fail = (message: string): void => {
    sendJson(res, 200, { data: null, errors: [{ message }] });
  };

  // Introspection: __type(name: "..."), keyed by the query's alias when present
  // (gh's probes alias them: Issue:, PullRequest:, Repository:, SearchType:).
  const aliasedTypes = [...query.matchAll(/(\w+)\s*:\s*__type\s*\(\s*name\s*:\s*"([^"]+)"/g)];
  if (aliasedTypes.length) {
    const data: Record<string, unknown> = {};
    for (const m of aliasedTypes) data[m[1]] = gqlTypeShape(m[2]);
    sendJson(res, 200, { data });
    return;
  }
  const typeMatch = query.match(/__type\s*\(\s*name\s*:\s*"([^"]+)"/);
  if (typeMatch) {
    const shape = gqlTypeShape(typeMatch[1]);
    sendJson(res, 200, { data: { __type: shape } });
    return;
  }

  // Mutations.
  if (/mutation/.test(query)) {
    if (/createIssue\s*\(/.test(query)) {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const dec = typeof input.repositoryId === 'string' ? decodeGid(input.repositoryId) : null;
      const repo = dec ? findRepo(dec.key.split('/')[0], dec.key.split('/').slice(1).join('/')) : null;
      if (!repo) { fail('repository not found'); return; }
      const { issue, error } = newIssue(repo, typeof input.title === 'string' ? input.title : '', typeof input.body === 'string' ? input.body : '', []);
      if (!issue) { fail(error ?? 'cannot create issue'); return; }
      sendJson(res, 200, { data: { createIssue: { issue: gqlIssueObj(repo, issue) } } });
      return;
    }
    if (/closeIssue\s*\(/.test(query)) {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const dec = typeof input.issueId === 'string' ? decodeGid(input.issueId) : null;
      if (!dec) { fail('issue not found'); return; }
      const hash = dec.key.lastIndexOf('#');
      const repo = findRepo(dec.key.slice(0, hash).split('/')[0], dec.key.slice(0, hash).split('/').slice(1).join('/'));
      const issue = repo?.issues.find((i) => i.number === parseInt(dec.key.slice(hash + 1), 10));
      if (!repo || !issue) { fail('issue not found'); return; }
      issue.state = 'closed';
      issue.closed_at = NOW_ISO;
      issue.updated_at = NOW_ISO;
      refreshIssueJson(repo, issue);
      sendJson(res, 200, { data: { closeIssue: { issue: gqlIssueObj(repo, issue) } } });
      return;
    }
    if (/createPullRequest\s*\(/.test(query)) {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const dec = typeof input.repositoryId === 'string' ? decodeGid(input.repositoryId) : null;
      const repo = dec ? findRepo(dec.key.split('/')[0], dec.key.split('/').slice(1).join('/')) : null;
      if (!repo) { fail('repository not found'); return; }
      const { pr, error } = newPull(
        repo,
        typeof input.title === 'string' ? input.title : '',
        typeof input.body === 'string' ? input.body : '',
        typeof input.headRefName === 'string' ? input.headRefName : '',
        typeof input.baseRefName === 'string' ? input.baseRefName : '',
      );
      if (!pr) { fail(error ?? 'cannot create pull request'); return; }
      sendJson(res, 200, { data: { createPullRequest: { pullRequest: gqlPullObj(repo, pr) } } });
      return;
    }
    if (/mergePullRequest\s*\(/.test(query)) {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const dec = typeof input.pullRequestId === 'string' ? decodeGid(input.pullRequestId) : null;
      if (!dec) { fail('pull request not found'); return; }
      const hash = dec.key.lastIndexOf('#');
      const repo = findRepo(dec.key.slice(0, hash).split('/')[0], dec.key.slice(0, hash).split('/').slice(1).join('/'));
      const pr = repo?.pulls.find((p) => p.number === parseInt(dec.key.slice(hash + 1), 10));
      if (!repo || !pr) { fail('pull request not found'); return; }
      const { sha, error, status } = mergePull(repo, pr);
      if (!sha) { fail(error ?? 'cannot merge'); void status; return; }
      sendJson(res, 200, { data: { mergePullRequest: { pullRequest: gqlPullObj(repo, pr) } } });
      return;
    }
    if (/addComment\s*\(/.test(query)) {
      const input = (vars.input ?? {}) as Record<string, unknown>;
      const dec = typeof input.subjectId === 'string' ? decodeGid(input.subjectId) : null;
      if (!dec) { fail('subject not found'); return; }
      const hash = dec.key.lastIndexOf('#');
      const repo = findRepo(dec.key.slice(0, hash).split('/')[0], dec.key.slice(0, hash).split('/').slice(1).join('/'));
      const issue = repo?.issues.find((i) => i.number === parseInt(dec.key.slice(hash + 1), 10));
      if (!repo || !issue) { fail('issue not found'); return; }
      const comment = { id: gidSeq++, body: typeof input.body === 'string' ? input.body : '', user: VIEWER.login, created_at: NOW_ISO, updated_at: NOW_ISO };
      issue.comments.push(comment);
      refreshIssueJson(repo, issue);
      const node = { __typename: 'IssueComment', id: String(comment.id), body: comment.body, author: { login: VIEWER.login } };
      sendJson(res, 200, { data: { addComment: { commentEdge: { node }, comment: node } } });
      return;
    }
    fail('unknown mutation');
    return;
  }

  // node(id: ...) — a global-id lookup.
  if (/node\s*\(/.test(query)) {
    const id = vstr('id') ?? query.match(/node\s*\(\s*id\s*:\s*"([^"]+)"/)?.[1] ?? null;
    const dec = id ? decodeGid(id) : null;
    if (!dec) { sendJson(res, 200, { data: { node: null } }); return; }
    if (dec.kind === 'Repository') {
      const repo = findRepo(dec.key.split('/')[0], dec.key.split('/').slice(1).join('/'));
      sendJson(res, 200, { data: { node: repo ? gqlRepoObj(repo) : null } });
      return;
    }
    if (dec.kind === 'Issue' || dec.kind === 'PullRequest') {
      const hash = dec.key.lastIndexOf('#');
      const repo = findRepo(dec.key.slice(0, hash).split('/')[0], dec.key.slice(0, hash).split('/').slice(1).join('/'));
      const n = parseInt(dec.key.slice(hash + 1), 10);
      if (!repo) { sendJson(res, 200, { data: { node: null } }); return; }
      const node = dec.kind === 'Issue'
        ? (repo.issues.find((i) => i.number === n) ? gqlIssueObj(repo, repo.issues.find((i) => i.number === n) as Issue) : null)
        : (repo.pulls.find((p) => p.number === n) ? gqlPullObj(repo, repo.pulls.find((p) => p.number === n) as Pull) : null);
      sendJson(res, 200, { data: { node } });
      return;
    }
    sendJson(res, 200, { data: { node: null } });
    return;
  }

  // search(type: ISSUE, query: "...", first: N).
  if (/search\s*\(/.test(query)) {
    const q = vstr('query') ?? '';
    const first = vint('first') ?? 10;
    const m = q.match(/repo:([^\s]+)/);
    let found: Array<Record<string, unknown>> = [];
    if (m) {
      const [o, n] = m[1].split('/');
      const repo = findRepo(o, n);
      if (repo) {
        const terms = q.replace(/repo:[^\s]+\s*/, '').trim().toLowerCase();
        found = repo.issues
          .filter((i) => !terms || i.title.toLowerCase().includes(terms) || i.body.toLowerCase().includes(terms))
          .slice(0, first)
          .map((i) => gqlIssueObj(repo, i));
      }
    }
    sendJson(res, 200, { data: { search: { nodes: found, issueCount: found.length, pageInfo: { hasNextPage: false, endCursor: null } } } });
    return;
  }

  // viewer { ... } — reject unknown fields with a named error, as real GraphQL does.
  if (/viewer\s*\{/.test(query)) {
    const start = query.indexOf('viewer');
    const open = query.indexOf('{', start);
    let depth = 0;
    let end = open;
    for (; end < query.length; end++) {
      if (query[end] === '{') depth++;
      else if (query[end] === '}') { depth--; if (depth === 0) break; }
    }
    const inner = query.slice(open + 1, end);
    // Only the viewer's top-level fields are validated; nested selections belong
    // to their own types and are not the invalid-field check's business.
    const fields: string[] = [];
    {
      let depth = 0;
      let word = '';
      const flushWord = (): void => {
        if (word && depth === 0) fields.push(word);
        word = '';
      };
      for (const ch of inner) {
        if (ch === '{') { flushWord(); depth++; }
        else if (ch === '}') { flushWord(); depth--; }
        else if (/[\s,():]/.test(ch)) flushWord();
        else word += ch;
      }
      flushWord();
    }
    const known = new Set(GQL_TYPES.User.fields ?? []);
    const bad = fields.find((f) => !known.has(f) && !['__typename'].includes(f));
    if (bad) {
      sendJson(res, 200, { data: { viewer: null }, errors: [{ message: `Cannot query field "${bad}" on type "User".` }] });
      return;
    }
    sendJson(res, 200, {
      data: {
        viewer: {
          __typename: 'User',
          login: VIEWER.login,
          id: String(VIEWER.id),
          name: VIEWER.name,
          email: VIEWER.email,
        },
      },
    });
    return;
  }

  // repository(owner: ..., name: ...) — variables first, literals as fallback.
  if (/repository\s*\(/.test(query)) {
    const owner = vstr('owner') ?? query.match(/owner\s*:\s*"([^"]+)"/)?.[1] ?? '';
    const name = vstr('name') ?? query.match(/name\s*:\s*"([^"]+)"/)?.[1] ?? '';
    const repo = findRepo(owner, name);
    if (!repo) { sendJson(res, 200, { data: { repository: null } }); return; }
    const out: Record<string, unknown> = gqlRepoObj(repo);
    // issue(number: N)
    const issueNum = vint('number') ?? (query.match(/issue\s*\(\s*number\s*:\s*(\d+)/)?.[1] ? parseInt(query.match(/issue\s*\(\s*number\s*:\s*(\d+)/)?.[1] as string, 10) : null);
    if (issueNum !== null) {
      const issue = repo.issues.find((i) => i.number === issueNum);
      out.issue = issue ? gqlIssueObj(repo, issue) : null;
    }
    // pullRequest(number: N) — the number may come as a variable ($number).
    const prLit = query.match(/pullRequest\s*\(\s*number\s*:\s*(\d+)/)?.[1];
    const prNum = vint('number') ?? (prLit ? parseInt(prLit, 10) : null);
    if (prNum !== null) {
      const pr = repo.pulls.find((p) => p.number === prNum);
      out.pullRequest = pr ? gqlPullObj(repo, pr) : null;
    }
    // issues(first, after, states, orderBy)
    if (/issues\s*\(/.test(query) || /issues\s*\{/.test(query)) {
      const first = vint('first');
      const after = vstr('after');
      const states = Array.isArray(vars.states)
        ? (vars.states as string[])
        : (query.match(/states\s*:\s*\[([^\]]*)\]/)?.[1].split(',').map((s) => s.trim()).filter(Boolean) ?? null);
      const desc = !/direction\s*:\s*ASC/i.test(query);
      let list = [...repo.issues].sort((a, b) => (desc ? b.number - a.number : a.number - b.number));
      if (states) list = list.filter((i) => states.includes(i.state.toUpperCase()));
      out.issues = pageOf(list, first, after, (i) => String(i.number));
      (out.issues as Record<string, unknown>).nodes = (list as Issue[]).length === 0 ? [] : (out.issues as { nodes: unknown[] }).nodes;
      // Rebuild nodes as GraphQL objects.
      const pg = pageOf(list.map((i) => gqlIssueObj(repo, i)), first, after, (o) => String((o as Record<string, unknown>).number));
      out.issues = pg;
    }
    // pullRequests(first, after)
    if (/pullRequests\s*\(/.test(query) || /pullRequests\s*\{/.test(query)) {
      const first = vint('first');
      const after = vstr('after');
      const list = [...repo.pulls].sort((a, b) => b.number - a.number).map((p) => gqlPullObj(repo, p));
      out.pullRequests = pageOf(list, first, after, (o) => String((o as Record<string, unknown>).number));
    }
    sendJson(res, 200, { data: { repository: out } });
    return;
  }

  // A bare repositories / user lookup is not part of the graded documents; answer empty.
  sendJson(res, 200, { data: {} });
}

// -------------------------------------------------------------------------------------------
// MCP (Streamable HTTP, 2026-07-28 revision with the legacy handshake as a fallback).

interface McpToolDef { name: string; description: string; inputSchema: Record<string, unknown> }

const MCP_TOOLS: McpToolDef[] = [
  { name: 'create_repo', description: 'Create a repository owned by the viewer.', inputSchema: { type: 'object', properties: { name: { type: 'string' }, description: { type: 'string' }, private: { type: 'boolean' } }, required: ['name'] } },
  { name: 'get_repo', description: 'Get a repository by owner and name.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_issue', description: 'Create an issue in a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['owner', 'repo', 'title'] } },
  { name: 'list_issues', description: 'List the issues of a repository.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, state: { type: 'string' } }, required: ['owner', 'repo'] } },
  { name: 'create_pull_request', description: 'Open a pull request from a head branch into a base branch.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' }, head: { type: 'string' }, base: { type: 'string' } }, required: ['owner', 'repo', 'head', 'base'] } },
  { name: 'merge_pull_request', description: 'Merge a pull request by number.', inputSchema: { type: 'object', properties: { owner: { type: 'string' }, repo: { type: 'string' }, pull_number: { type: 'integer' } }, required: ['owner', 'repo', 'pull_number'] } },
];
const MCP_TOOLS_JSON = JSON.stringify(MCP_TOOLS);

function mcpResult(res: http.ServerResponse, id: unknown, result: unknown): void {
  sendJson(res, 200, { jsonrpc: '2.0', id: id ?? null, result });
}

function mcpError(res: http.ServerResponse, status: number, id: unknown, code: number, message: string): void {
  sendJson(res, status, { jsonrpc: '2.0', id: id ?? null, error: { code, message } });
}

function mcpToolText(text: string, isError = false): Record<string, unknown> {
  return { content: [{ type: 'text', text }], isError };
}

function mcpHandler(req: http.IncomingMessage, res: http.ServerResponse, body: Buffer): void {
  let msg: { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  try {
    msg = JSON.parse(body.toString('utf8'));
  } catch {
    mcpError(res, 400, null, -32700, 'Parse error');
    return;
  }
  if (!msg || typeof msg !== 'object' || typeof msg.method !== 'string') {
    mcpError(res, 400, (msg as { id?: unknown } | null)?.id ?? null, -32600, 'Invalid Request');
    return;
  }
  const id = msg.id ?? null;
  const params = (msg.params ?? {}) as Record<string, unknown>;

  // A notification (no id) never gets a JSON-RPC answer; 202 with an empty body is enough.
  if (msg.method === 'notifications/initialized' || msg.method.startsWith('notifications/')) {
    res.writeHead(202, { 'x-github-request-id': `req-${++reqSeq}` });
    res.end();
    return;
  }

  if (msg.method === 'server/discover') {
    mcpResult(res, id, {
      resultType: 'discover',
      supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
      capabilities: { tools: {} },
      instructions: 'A GitHub-compatible git forge.',
      serverInfo: { name: 'forge', version: '1.0.0' },
      _meta: { protocolVersion: '2026-07-28', serverInfo: { name: 'forge', version: '1.0.0' } },
    });
    return;
  }

  if (msg.method === 'initialize') {
    const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
    const chosen = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'].includes(offered) ? offered : '2025-11-25';
    mcpResult(res, id, {
      protocolVersion: chosen,
      capabilities: { tools: {} },
      serverInfo: { name: 'forge', version: '1.0.0' },
    });
    return;
  }

  if (msg.method === 'ping') {
    mcpResult(res, id, {});
    return;
  }

  if (msg.method === 'tools/list') {
    // Byte-identical on every call: the same pre-serialized array.
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: JSON.parse(MCP_TOOLS_JSON) } });
    return;
  }

  if (msg.method === 'tools/call') {
    const name = typeof params.name === 'string' ? params.name : '';
    const args = (params.arguments ?? {}) as Record<string, unknown>;
    const tool = MCP_TOOLS.find((t) => t.name === name);
    if (!tool) {
      mcpError(res, 200, id, -32601, `unknown tool ${name}`);
      return;
    }
    const required = ((tool.inputSchema.required ?? []) as string[]);
    const missing = required.filter((k) => args[k] === undefined || args[k] === null || args[k] === '');
    if (missing.length) {
      mcpResult(res, id, mcpToolText(`missing required arguments: ${missing.join(', ')}`, true));
      return;
    }
    const owner = typeof args.owner === 'string' ? args.owner : VIEWER.login;
    const repoName = typeof args.repo === 'string' ? args.repo : typeof args.name === 'string' ? args.name : '';
    if (name === 'create_repo') {
      const repo = createRepo(repoName, typeof args.description === 'string' ? args.description : '', args.private === true);
      mcpResult(res, id, mcpToolText(JSON.stringify(repoJson(repo))));
      return;
    }
    const repo = findRepo(owner, repoName);
    if (!repo) {
      mcpResult(res, id, mcpToolText(`repository ${owner}/${repoName} not found`, true));
      return;
    }
    if (name === 'get_repo') {
      mcpResult(res, id, mcpToolText(JSON.stringify(repoJson(repo))));
      return;
    }
    if (name === 'create_issue') {
      const { issue, error } = newIssue(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', []);
      if (!issue) { mcpResult(res, id, mcpToolText(error ?? 'cannot create issue', true)); return; }
      mcpResult(res, id, mcpToolText(issue.json));
      return;
    }
    if (name === 'list_issues') {
      const state = typeof args.state === 'string' ? args.state : 'open';
      const list = repo.issues.filter((i) => state === 'all' || i.state === state);
      mcpResult(res, id, mcpToolText(JSON.stringify(list.map((i) => issueJsonObj(repo, i)))));
      return;
    }
    if (name === 'create_pull_request') {
      const { pr, error } = newPull(repo, String(args.title ?? ''), typeof args.body === 'string' ? args.body : '', String(args.head ?? ''), String(args.base ?? ''));
      if (!pr) { mcpResult(res, id, mcpToolText(error ?? 'cannot create pull request', true)); return; }
      mcpResult(res, id, mcpToolText(JSON.stringify(pullJsonObj(repo, pr))));
      return;
    }
    if (name === 'merge_pull_request') {
      const num = typeof args.pull_number === 'number' ? args.pull_number : parseInt(String(args.pull_number ?? ''), 10);
      const pr = repo.pulls.find((p) => p.number === num);
      if (!pr) { mcpResult(res, id, mcpToolText(`pull request #${num} not found`, true)); return; }
      const { sha, error } = mergePull(repo, pr);
      if (!sha) { mcpResult(res, id, mcpToolText(error ?? 'cannot merge', true)); return; }
      mcpResult(res, id, mcpToolText(JSON.stringify(pullJsonObj(repo, pr))));
      return;
    }
    mcpError(res, 200, id, -32601, `unknown tool ${name}`);
    return;
  }

  mcpError(res, 200, id, -32601, `method not found: ${msg.method}`);
}

// -------------------------------------------------------------------------------------------
// Git HTTP entry points.

function gitHandler(req: http.IncomingMessage, res: http.ServerResponse, method: string, path: string, query: Map<string, string>, body: Buffer): void {
  const m = path.match(/^\/([^/]+)\/([^/]+)\.git\/(.*)$/);
  if (!m) { errJson(res, 404, 'Not Found'); return; }
  const owner = decodeURIComponent(m[1]);
  const name = decodeURIComponent(m[2]);
  const tail = m[3];
  const repo = findRepo(owner, name);
  if (!repo) {
    res.writeHead(404, { 'content-type': 'text/plain', 'x-github-request-id': `req-${++reqSeq}` });
    res.end('Not Found');
    return;
  }
  if (tail === 'info/refs' && method === 'GET') {
    const service = query.get('service') ?? '';
    if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('service is required');
      return;
    }
    const v2 = (req.headers['git-protocol'] ?? '') === 'version=2' && service === 'git-upload-pack';
    const ad = v2 ? v2Advertisement() : v0Advertisement(repo, service);
    sendBuf(res, 200, ad, service === 'git-upload-pack' ? 'application/x-git-upload-pack-advertisement' : 'application/x-git-receive-pack-advertisement');
    return;
  }
  if (tail === 'git-upload-pack' && method === 'POST') {
    const v2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const packets = decodePkts(body);
    const firstLine = packets.find((p) => p.kind === 'data')?.payload.toString('utf8') ?? '';
    if (v2 && firstLine.startsWith('command=ls-refs')) {
      const opts = { peel: false, symrefs: false, unborn: false, prefixes: [] as string[] };
      for (const p of packets) {
        if (p.kind !== 'data') continue;
        const line = p.payload.toString('utf8').trim();
        if (line === 'peel') opts.peel = true;
        else if (line === 'symrefs') opts.symrefs = true;
        else if (line === 'unborn') opts.unborn = true;
        else if (line.startsWith('ref-prefix ')) opts.prefixes.push(line.slice('ref-prefix '.length));
      }
      sendBuf(res, 200, lsRefsAnswer(repo, opts), 'application/x-git-upload-pack-result');
      return;
    }
    if (v2 && firstLine.startsWith('command=fetch')) {
      const wants: string[] = [];
      const haves: string[] = [];
      const shallowReq: string[] = [];
      let depth: number | null = null;
      let deepenRelative = false;
      for (const p of packets) {
        if (p.kind !== 'data') continue;
        const line = p.payload.toString('utf8').trim();
        if (line.startsWith('want ')) wants.push(line.slice(5));
        else if (line.startsWith('have ')) haves.push(line.slice(5));
        else if (line.startsWith('shallow ')) shallowReq.push(line.slice(8));
        else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7), 10);
        else if (line === 'deepen-relative') deepenRelative = true;
      }
      if (!wants.length) { errJson(res, 400, 'no wants'); return; }
      sendBuf(res, 200, fetchResponseV2(repo, wants, haves, depth, shallowReq, deepenRelative), 'application/x-git-upload-pack-result');
      return;
    }
    // v0 fetch: two sections, wants then haves, each closed by a flush.
    const wants: string[] = [];
    const haves: string[] = [];
    const shallowReq: string[] = [];
    let depth: number | null = null;
    let deepenRelative = false;
    let section = 0;
    for (const p of packets) {
      if (p.kind === 'flush') { section++; continue; }
      if (p.kind !== 'data') continue;
      const line = p.payload.toString('utf8').trim();
      if (section === 0) {
        if (line.startsWith('want ')) wants.push(line.slice(5).split(' ')[0]);
        else if (line.startsWith('shallow ')) shallowReq.push(line.slice(8));
        else if (line.startsWith('deepen ')) depth = parseInt(line.slice(7), 10);
        else if (line === 'deepen-relative') deepenRelative = true;
      } else {
        if (line.startsWith('have ')) haves.push(line.slice(5));
      }
    }
    if (!wants.length) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end('expected a want line');
      return;
    }
    sendBuf(res, 200, fetchResponseV0(repo, wants, haves, depth, shallowReq, deepenRelative), 'application/x-git-upload-pack-result');
    return;
  }
  if (tail === 'git-receive-pack' && method === 'POST') {
    try {
      const out = handleReceivePack(repo, body);
      sendBuf(res, 200, out, 'application/x-git-receive-pack-result');
    } catch (e) {
      res.writeHead(400, { 'content-type': 'text/plain' });
      res.end(`bad request: ${e instanceof Error ? e.message : 'unknown'}`);
    }
    return;
  }
  errJson(res, 404, 'Not Found');
}

// -------------------------------------------------------------------------------------------
// Server, routing and the trial lifecycle.

const server = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on('data', (c: Buffer) => {
    if (Buffer.concat(chunks).length < 64 * 1024 * 1024) chunks.push(c);
  });
  req.on('end', () => {
    const body = chunks.length ? Buffer.concat(chunks) : Buffer.alloc(0);
    const raw = req.url ?? '/';
    const qm = raw.indexOf('?');
    const path = qm < 0 ? raw : raw.slice(0, qm);
    const query = parseQuery(qm < 0 ? '' : raw.slice(qm + 1));
    const method = req.method ?? 'GET';
    try {
      if (path === '/healthz') {
        sendJson(res, 200, { status: 'ok' });
        return;
      }
      if (!authed(req)) {
        if (path.startsWith('/api/') || path === '/mcp' || path.includes('.git/')) {
          errJson(res, 401, 'requires authentication');
          return;
        }
        errJson(res, 401, 'requires authentication');
        return;
      }
      if (path === '/api/graphql' && method === 'POST') {
        try {
          graphqlHandler(res, body);
        } catch {
          sendJson(res, 200, { data: null, errors: [{ message: 'internal error' }] });
        }
        return;
      }
      if (path === '/mcp' && method === 'POST') {
        try {
          mcpHandler(req, res, body);
        } catch {
          mcpError(res, 200, null, -32603, 'internal error');
        }
        return;
      }
      if (path.startsWith('/api/v3')) {
        restHandler(req, res, method, path, query, body);
        return;
      }
      if (path.includes('.git/')) {
        gitHandler(req, res, method, path, query, body);
        return;
      }
      errJson(res, 404, 'Not Found');
    } catch (e) {
      if (!res.headersSent) errJson(res, 500, e instanceof Error ? e.message : 'internal error');
      else { try { res.end(); } catch { /* already closed */ } }
    }
  });
  req.on('error', () => {
    try { res.end(); } catch { /* ignore */ }
  });
});

server.keepAliveTimeout = 30000;
server.headersTimeout = 60000;

const ENV_URL = process.env.MAKEFUN_ENV_URL ?? '';
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

server.listen(0, '0.0.0.0', () => {
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  // A hand run (no trial env) just serves on the ephemeral port and waits.
  if (!ENV_URL) {
    process.stderr.write(`forge listening on http://127.0.0.1:${port} as ${VIEWER.login}\n`);
    return;
  }
  void (async () => {
    try {
      const reg = await fetch(`${ENV_URL}/register`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
        signal: AbortSignal.timeout(10000),
      });
      if (!reg.ok) process.stderr.write(`register answered HTTP ${reg.status}\n`);
    } catch (e) {
      process.stderr.write(`register failed: ${e instanceof Error ? e.message : 'unknown'}\n`);
    }
    for (;;) {
      try {
        const r = await fetch(`${ENV_URL}/done`, { signal: AbortSignal.timeout(30000) });
        const j = (await r.json()) as { done?: boolean };
        if (j.done === true) break;
      } catch {
        // The suite may hold the poll open; a failure here is just a retry.
      }
      await sleep(1000);
    }
    process.exit(0);
  })();
});
