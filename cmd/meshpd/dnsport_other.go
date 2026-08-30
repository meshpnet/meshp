//go:build !windows

package main

// dnsListenPort is whatever the kernel has spare.
//
// Zero asks for any, which is what keeps meshp out of a fight with whatever this machine was
// already using for DNS. Both platforms that get here can be told which port afterwards.
const dnsListenPort = 0
