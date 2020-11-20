package main

import (
	"github.com/tw-bc-group/fabric-ca-gm/cmd/fabric-ca-zh/cmd"
	"os"
)

func main() {
	if err := RunMain(os.Args); err != nil {
		os.Exit(1)
	}
}

func RunMain(args []string) error {
	// Save the os.Args
	saveOsArgs := os.Args
	os.Args = args

	cmdName := ""
	if len(args) > 1 {
		cmdName = args[1]
	}

	err := cmd.NewCommand(cmdName).Execute()

	// Restore original os.Args
	os.Args = saveOsArgs

	return err
}
