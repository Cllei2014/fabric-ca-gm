package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	longName  = "Hyperledger Fabric Zhong Huan Certificate Authority Tool"
	shortName = "fabric-ca-zh"
	cmdName   = "fabric-ca-zh"
)

type Command struct {
	name    string
	rootCmd *cobra.Command
	myViper *viper.Viper
}

func NewCommand(name string) *Command {
	cmd := &Command{
		name:    name,
		myViper: viper.New(),
	}
	cmd.init()
	return cmd
}

func (cmd *Command) init() {
	cmd.rootCmd = &cobra.Command{
		Use:   cmdName,
		Short: shortName,
		Long:  longName,
	}
	cmd.rootCmd.AddCommand(NewCsrCmd())
	cmd.rootCmd.AddCommand(NewICACmd())
}

func (cmd *Command) Execute() error {
	return cmd.rootCmd.Execute()
}

func printOutput(keyID, output string) {
	fmt.Printf("-----BEGIN KEY ID-----\n%s\n-----END KEY ID-----\n\n%s", keyID, output)
}
