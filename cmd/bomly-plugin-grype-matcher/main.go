// Command bomly-plugin-grype-matcher serves the Grype matcher as a managed Bomly
// plugin over the HashiCorp go-plugin gRPC transport. The binary is launched
// and supervised by Bomly; it is not meant to be run by hand.
package main

import (
	"github.com/bomly-dev/bomly-plugin-grype-matcher/plugin"

	"github.com/bomly-dev/bomly-sdk/runtime"
)

func main() { runtime.ServeModule(plugin.Module()) }
