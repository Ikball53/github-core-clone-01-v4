# Forge — a zero-dependency single-file GitHub-compatible git forge

[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![make.fun · github-core-clone-01 rank](https://make.fun/badge/github-core-clone-01/Ikball53/github-core-clone-01-v4/rank.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![make.fun · github-core-clone-01 reward](https://make.fun/badge/github-core-clone-01/Ikball53/github-core-clone-01-v4/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

One file, no dependencies, no git binary: `main.ts` serves the whole forge from
memory — git smart HTTP (protocol v0 + v2, fetch/push, shallow clones, sideband
reports), REST v3, GraphQL and MCP — on Node 22's standard library alone.

## Run

```sh
node main.ts
```

The program binds an ephemeral port, registers it with the trial environment at
`$MAKEFUN_ENV_URL`, serves until the suite reports done, then exits 0. With no
trial environment set it just serves on the ephemeral port and waits.

## How it is fast

- The clone pack, the v0/v2 advertisements and the ls-refs answer are cached per
  repository and rebuilt only when a ref moves, so the 50 concurrent depth-1
  clones in the benchmark share one pack build.
- Issue JSON is pre-serialized at write time, so the 2,000-read workload answers
  from a cached string.
- Packs are emitted with zlib level 0 (stored blocks): the wire needs valid zlib,
  not tiny zlib, and stored blocks are the cheapest correct encoding.
- All timestamps come from `MAKEFUN_TRIAL_NOW`, so a live pass and its replay
  leave byte-identical state.

## Layout

- `main.ts` — the whole forge (entrypoint).
- `.makefun/owner.json` — the owner's wallet.
- `LICENSE` — MIT.
