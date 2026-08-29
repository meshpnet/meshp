# ADR-0028: The Windows data plane is WinTun, shipped beside the binary

- **Status:** accepted
- **Date:** 2026-08-29

## Context

ADR-0015 says meshp has to move packets on Linux, Windows, macOS, Android and iOS. Linux has
since the beginning; macOS does as of #171. Windows is next, and #144 records the rule the
macOS work established: **a platform's CI job lands in the same pull request as the code it
covers**, because a build-only job described as coverage is the failure ADR-0018 is about
wearing a green tick.

Windows has no WireGuard in the kernel and no utun. What it has is WinTun, a signed kernel
driver from the WireGuard project that presents a layer-3 adapter to userspace, and which
`wireguard-go` already knows how to drive: `tun_windows.go` ships in the module this project
already depends on, and `golang.zx2c4.com/wintun` — the Go wrapper — is already an indirect
dependency. The Go side of this costs nothing.

The runtime side is where the questions are, and they are the kind this project has learned
to answer on a real machine rather than by reading. Before #169, reasoning about `pfctl` was
wrong; before #171, reasoning about `route(8)` was wrong twice.

## What a hosted Windows runner actually does

Established on `windows-latest` — Windows Server 2025 Datacenter, build 10.0.26100 — with a
throwaway workflow that is not kept. What it proved is below.

**The runner is elevated.** `IsInRole(Administrator)` is true. Creating a WinTun adapter
installs a driver, so this was the gating question: without it, a Windows job could only ever
compile.

**An adapter can be created, named, and closed.** `tun.CreateTUN("meshp-probe", 1420)`
returned a device reporting that name and that MTU, and closing it left nothing behind —
`Get-NetAdapter` afterwards showed only the runner's own interfaces.

**`wintun.dll` must sit beside the executable.** Windows resolves a DLL relative to the
binary's own directory, not the working directory, so `go run` — which builds into a
temporary directory — cannot find it however the repository is laid out. Putting the DLL in
`System32` works too. Both were tried; both created an adapter.

**The distribution is four DLLs, a header, a README and a licence.** amd64, arm, arm64 and
x86.

## Decision

**WinTun, with `wintun.dll` shipped beside `meshpd.exe`.**

Not installed into `System32`. That is a shared system directory with no clean undo, and this
project has twice decided against writing into one on exactly that argument — `/etc/resolv.conf`
in ADR-0021 and `/etc/pf.conf` in ADR-0026. A file beside the binary is removed by removing
meshp.

**Pinned by hash, not vendored.** The release build fetches the published zip from
wintun.net and checks it against a SHA-256 recorded in the repository; today that is
`07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51`, containing an amd64 DLL
of `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`. A binary in git is a
binary nobody reviews and every clone carries; a pinned hash is the same guarantee with the
bytes fetched once, and upgrading it is a diff a person can see.

**The licence ships with it**, because it requires that.

## The licensing consequence, stated plainly

`wintun.dll` is **not open source.** The Go wrapper is MIT; the DLL is under WireGuard LLC's
Prebuilt Binaries License, which is a proprietary licence: no modification, no reverse
engineering, no removing notices, and no redistribution — with one exception, which is the
one meshp needs. It permits distributing the DLL alongside other software that uses it only
through the documented `wintun.h` interface. That is precisely what meshp does, through
`golang.zx2c4.com/wintun`, which is what makes this arrangement allowed rather than merely
common.

So: **meshp's own code stays Apache-2.0 (ADR-0009), and meshp's Windows distribution is not
wholly open source.** Anybody redistributing meshp for Windows inherits the same permission
and the same conditions. Anybody who needs a wholly free distribution can omit the DLL and
tell operators to install WinTun themselves, and meshp will find it: the loader looks beside
the binary and then where Windows looks.

This is worth being loud about rather than discovering later, and it is the same trade
WireGuard's own Windows client makes. There is no second implementation of a layer-3 adapter
for Windows to choose instead.

## Consequences

**A Windows build is two files, not one.** Packaging, the release workflow and the
installation instructions all have to carry that, and a `meshpd.exe` on its own will fail at
the first tunnel with a DLL-not-found error rather than at start-up. Reporting that clearly
is part of the implementation rather than a nicety.

**`go run` will never work for anything that opens a tunnel on Windows.** Developer
instructions have to say `go build` and run the binary from where the DLL is. This is the
first thing that will confuse somebody, and it confused this probe.

**Windows CI is real from the first slice.** An adapter can be created on a hosted runner,
so the job that lands with the tunnel exercises the tunnel. What is not yet established is
whether a packet crosses one — that is the implementation's question to answer, exactly as it
was for macOS in #152.

**The kind is `userspace`.** ADR-0015 requires that be surfaced in `meshp status` and in the
heartbeat, for the reason it does on macOS: a silent fallback turns "why is this host a tenth
the speed" into an unanswerable question.

## Alternatives considered

**Require the operator to install WinTun or the WireGuard for Windows client.** Keeps meshp's
distribution wholly Apache-2.0. Rejected as the default because it makes the first run fail
for everybody, and the failure is a DLL error rather than anything a person can act on. It
remains available and supported — the loader finds an installed DLL — and is the right answer
for anybody who needs a distribution with no proprietary parts in it.

**Vendor the DLL into the repository.** Simpler builds, no fetch. Rejected because a binary
in git is one nobody reviews, every clone carries it forever, and updating it is a diff that
shows nothing. The hash gives the same integrity guarantee and an upgrade is legible.

**Write a driver.** A signed Windows kernel driver needs an EV certificate, Microsoft
attestation signing, and an ongoing relationship with WHQL. It is not a slice; it is a
company's worth of work to reimplement something the WireGuard project already gives away.

**Use Windows' built-in VPN plumbing.** There is no in-box WireGuard implementation. The
platform's IKEv2 and SSTP stacks are not the protocol meshp speaks.
