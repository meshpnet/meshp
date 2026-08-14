//go:build !linux

package nftables

// EnableForwarding does nothing off Linux, where there is no data plane to forward with.
func EnableForwarding() ([]string, error) { return nil, nil }
