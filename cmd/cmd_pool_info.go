package cmd

import (
	"context"
	"fmt"
	"github.com/forta-network/forta-core-go/registry"
	"github.com/forta-network/forta-core-go/security"
	"github.com/forta-network/forta-node/store"
	"github.com/spf13/cobra"
)

func handleFortaPoolInfo(cmd *cobra.Command, args []string) error {
	scannerKey, err := security.LoadKeyWithPassphrase(cfg.KeyDirPath, cfg.Passphrase)
	if err != nil {
		return fmt.Errorf("failed to load scanner key: %v", err)
	}
	regClient, err := store.GetRegistryClient(context.Background(), cfg, registry.ClientConfig{
		JsonRpcUrl: cfg.Registry.JsonRpc.Url,
		ENSAddress: cfg.ENSConfig.ContractAddress,
		Name:       "registry-client",
		PrivateKey: scannerKey.PrivateKey,
	})
	if err != nil {
		return fmt.Errorf("failed to create registry client: %v", err)
	}
	regClient.SetRegistryChainID(cfg.Registry.ChainID)
	scanner, err := regClient.GetPoolScanner(scannerKey.Address.Hex())
	if err != nil {
		return fmt.Errorf("failed to get scanner from registry: %v", err)
	}
	fmt.Println(scanner.PoolID)
	return nil
}
