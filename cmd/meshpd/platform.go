package main

import "runtime"

// osName is separated so tests can exercise the per-platform default paths
// without building for each GOOS.
func osName() string { return runtime.GOOS }
