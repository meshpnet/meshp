//go:build windows

package main

// dnsListenPort is 53 on Windows, because nothing else is expressible.
//
// See dnsListenAddr. The cost is real and ADR-0029 accepts it: this is the one platform where
// meshp competes for a well-known port, and a machine already running something on 53 — WSL
// and Docker Desktop both can — gets no name resolution from meshp. It fails at start-up,
// loudly, rather than resolving into a hole.
const dnsListenPort = 53
