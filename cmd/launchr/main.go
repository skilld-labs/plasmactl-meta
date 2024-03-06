// Package executes Launchr application.
package main

import (
	"os"

	"github.com/launchrctl/launchr"

	_ "github.com/skilld-labs/plasmactl-meta"
)

func main() {
	os.Exit(launchr.Run())
}
