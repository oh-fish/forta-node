package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

func handleFortaChainInfo(cmd *cobra.Command, args []string) error {
	fmt.Println(cfg.ChainID)
	return nil
}
