# Xray-core (fork)

Fork of [XTLS/Xray-core](https://github.com/XTLS/Xray-core).

## Upstream version

Based on **Xray-core v26.4.17**, at upstream tag
[`v26.4.17`](https://github.com/XTLS/Xray-core/releases/tag/v26.4.17)
(commit [`b4650360`](https://github.com/XTLS/Xray-core/commit/b4650360)).

Pinned to **v26.4.17** on purpose: it is the last upstream release that still
supports the legacy `reverse` (bridge/portal) config. Upstream removed it in
**v26.4.25** (migrated to VLESS Reverse Proxy), so newer releases fail to start
with existing legacy-reverse configs.

## Changes in this fork

- **Shadowsocks: per-user `method` falls back to the server-level cipher.**
  When a Shadowsocks user entry omits `"method"`, the server-level `method`
  is inherited instead of failing with an unsupported-cipher error.
  (`infra/conf/shadowsocks.go`)

  Patch based on: [Sir-MmD/xray-core-ss-fix](https://github.com/Sir-MmD/xray-core-ss-fix)
  (`shadowsocks.patch`).

## In short

This is a patched build of Xray-core, pinned to a version that still supports
legacy `reverse`, that also no longer throws the `unsupported cipher method`
error for Shadowsocks inbounds. Users defined without their own `method` now
inherit the inbound's server-level cipher, so a valid Shadowsocks inbound config
works out of the box.

## One-line Compilation

### Windows (PowerShell)

```powershell
$env:CGO_ENABLED=0
go build -o xray.exe -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Linux / macOS

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -v ./main
```

### Reproducible Releases

Make sure that you are using the same Go version, and remember to set the git commit id (7 bytes):

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```

For Android:

```bash
GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=/path/to/aarch64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=/path/to/x86_64-linux-android24-clang go build -o xray -trimpath -buildvcs=false -gcflags="all=-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid= -checklinkname=0" -v ./main
```

If you are compiling a 32-bit MIPS/MIPSLE target, use this command instead:

```bash
CGO_ENABLED=0 go build -o xray -trimpath -buildvcs=false -gcflags="-l=4" -ldflags="-X github.com/xtls/xray-core/core.build=REPLACE -s -w -buildid=" -v ./main
```
