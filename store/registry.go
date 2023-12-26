package store

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"sync"
	"time"

	"github.com/ipfs/go-cid"
	log "github.com/sirupsen/logrus"

	"github.com/forta-network/forta-core-go/ens"
	"github.com/forta-network/forta-core-go/manifest"
	"github.com/forta-network/forta-core-go/registry"
	"github.com/forta-network/forta-core-go/utils"
	"github.com/forta-network/forta-node/config"
	"github.com/forta-network/forta-node/store/sharding"
)

var (
	errInvalidBot = errors.New("invalid bot")
	ErrLocalMode  = errors.New("feature not available (private/local registry)")
)

const (
	// This is the force reload interval that helps us ignore the on-chain assignment
	// list hash. This helps avoid getting stuck with bad state.
	//
	// WARNING: This also affects how fast the nodes react to shard ID changes
	// because the bot assignment hash may not change for a scanner when
	// the scanner list for a bot changes (i.e. when another scanner is unassigned).
	assignmentForceReloadInterval = time.Minute * 5
)

type RegistryStore interface {
	FindAgentGlobally(agentID string) (*config.AgentConfig, error)
	GetAgentsIfChanged(scanner string) ([]config.AgentConfig, bool, error)
}

type registryStore struct {
	ctx context.Context
	bms BotManifestStore
	rc  registry.Client
	cfg config.Config

	lastUpdate           time.Time
	lastCompletedVersion string
	loadedBots           []config.AgentConfig
	invalidAssignments   []*registry.Assignment
	mu                   sync.Mutex
}

func (rs *registryStore) GetAgentsIfChanged(scanner string) ([]config.AgentConfig, bool, error) {
	// because we peg the latest block, it can be problematic if this is called concurrently
	rs.mu.Lock()
	defer rs.mu.Unlock()

	hash, err := rs.rc.GetAssignmentHash(scanner)
	if err != nil {
		return nil, false, err
	}

	shouldUpdate := rs.lastCompletedVersion != hash.Hash ||
		time.Since(rs.lastUpdate) > assignmentForceReloadInterval
	if !shouldUpdate {
		return nil, false, nil
	}

	if err := rs.rc.PegLatestBlock(); err != nil {
		return nil, false, err
	}
	defer rs.rc.ResetOpts()

	var (
		loadedBots         []config.AgentConfig
		invalidAssignments []*registry.Assignment
		failedLoadingAny   bool
	)

	chainId := big.NewInt(int64(rs.cfg.ChainID))
	assignments, err := rs.rc.GetAssignmentList(nil, chainId, scanner)
	if err != nil {
		return nil, false, err
	}

	for _, assignment := range assignments {
		logger := log.WithField("botId", assignment.AgentID)
		// https://app.forta.network/bot/XXX
		// if already invalidated, remember it for next time
		// block-botId-1: 0xa20699d82a7b3f3aef3a4e861efa46efb1ecbabac6d78a1d842f23c655fb0205
		//  - stupid request page 404 handler error.
		// block-botId-2: 0xa53515a09b38933c89ceea3edc4fbb42614cd270b356d93d1eea25779f64eff1
		//  - checking json rpc or checking jwt-provider
		// block-botId-3: 0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91
		//  - stupid bsc bot that make rpc crash
		// block-botId-4: 0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3
		//  - stupid bsc bot that make rpc crash
		// block-botId-5: 0x4616413fd08079e4ae853502632940ca74110e68d73321eafed156cc7475d9f2
		//  -
		if rs.isInvalidBot(assignment) ||
			assignment.AgentID == "0xa20699d82a7b3f3aef3a4e861efa46efb1ecbabac6d78a1d842f23c655fb0205" ||
			assignment.AgentID == "0xa53515a09b38933c89ceea3edc4fbb42614cd270b356d93d1eea25779f64eff1" ||
			assignment.AgentID == "0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91" ||
			assignment.AgentID == "0x4c7e56a9a753e29ca92bd57dd593bdab0c03e762bdd04e2bc578cb82b842c1f3" ||
			assignment.AgentID == "0x4616413fd08079e4ae853502632940ca74110e68d73321eafed156cc7475d9f2" ||
			assignment.AgentID == "0x1a69f5ec8ef436e4093f9ec4ce1a55252b7a9a2d2c386e3f950b79d164bc99e0" ||
			assignment.AgentID == "0x3172685467b021a6e6b9b0080edbf26e98d37eecd1ac90e89a8fa73b26e04e51" ||
			assignment.AgentID == "0x4616413fd08079e4ae853502632940ca74110e68d73321eafed156cc7475d9f2" ||
			assignment.AgentID == "0xa66ad2bed104042c3606d5a75f13e51ddfa17c1344f40544f983cb25f748fb39" ||
			assignment.AgentID == "0xc229915675d683a13e69ebc4a9ddd9f2b86712ed6cad8c33180811e03499aded" ||
			assignment.AgentID == "0x13a144dad9a1b11307fa94845d835a34e772b2875401bdc78b8cf528b19927a4" ||
			assignment.AgentID == "0x9839061a67e5e7fd5e11b70cc6493d95231a14c96915d7307f0337384865b39b" ||
			assignment.AgentID == "0x715c40c11a3e24f3f21c3e2db1c109bba358ccfcbceada84ee1e0f4dba4410e7" ||
			assignment.AgentID == "0xac82fb2a572c7c0d41dc19d24790db17148d1e00505596ebe421daf91c837799" ||
			assignment.AgentID == "0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c" ||
			assignment.AgentID == "0x617c356a4ad4b755035ef8024a87d36d895ee3cb0864e7ce9b3cf694dd80c82a" ||
			assignment.AgentID == "0x8badbf2ad65abc3df5b1d9cc388e419d9255ef999fb69aac6bf395646cf01c14" ||
			assignment.AgentID == "0x1d646c4045189991fdfd24a66b192a294158b839a6ec121d740474bdacb3ab23" {
			invalidAssignments = append(invalidAssignments, assignment)
			logger.Warn("invalid bot - skipping")
			continue
		}

		// try loading the rest of the unrecognized bots
		botCfg, err := rs.loadAssignment(assignment)
		switch {
		case err == nil: // yay
			// get sharding information
			loadedBots = append(loadedBots, *botCfg) // remember for next time
			logger.Info("successfully loaded bot")

		case errors.Is(err, errInvalidBot):
			invalidAssignments = append(invalidAssignments, assignment) // remember for next time
			logger.WithError(err).Warn("invalid bot - skipping")
		default:
			failedLoadingAny = true
			logger.WithError(err).Warn("could not load bot - skipping")
			// ignore agent and move on by not returning the error
			// it will not be recognized next time and will be retried above
			continue
		}
	}

	// failed to load all: forget that this attempt existed
	// not doing this can cause getting stuck with the latest hash and zero agents
	if len(loadedBots) == 0 && failedLoadingAny {
		return nil, false, errors.New("loaded zero bots")
	}

	// remember the bots and the update time next time
	rs.loadedBots = loadedBots
	rs.invalidAssignments = invalidAssignments
	rs.lastUpdate = time.Now()

	if failedLoadingAny {
		log.Warn("failed loading some of the bots - keeping the previous list version")
	} else {
		rs.lastCompletedVersion = hash.Hash // remember next time so we don't retry the same list
	}

	return loadedBots, true, nil
}

func (rs *registryStore) FindAgentGlobally(agentID string) (*config.AgentConfig, error) {
	agt, err := rs.rc.GetAgent(agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to get the latest ref: %v, agentID: %s", err, agentID)
	}

	botCfg, _, err := loadBot(rs.ctx, rs.cfg, rs.bms, agentID, agt.Manifest, agt.Owner)
	return botCfg, err
}

func (rs *registryStore) getLoadedBot(manifest string) (config.AgentConfig, bool) {
	for _, loadedBot := range rs.loadedBots {
		if manifest == loadedBot.Manifest {
			return loadedBot, true
		}
	}
	return config.AgentConfig{}, false
}

func (rs *registryStore) isInvalidBot(bot *registry.Assignment) bool {
	for _, invalidBot := range rs.invalidAssignments {
		if bot.AgentManifest == invalidBot.AgentManifest {
			return true
		}
	}
	return false
}

func loadBot(ctx context.Context, cfg config.Config, bms BotManifestStore, agentID string, ref string, owner string) (*config.AgentConfig, *manifest.SignedAgentManifest, error) {
	_, err := cid.Parse(ref)
	if len(ref) == 0 || err != nil {
		return nil, nil, fmt.Errorf("%w: invalid bot cid '%s'", errInvalidBot, ref)
	}

	signedManifest, err := bms.GetBotManifest(ctx, ref)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load the bot manifest: %v", err)
	}

	if signedManifest.Manifest.ImageReference == nil {
		return nil, nil, fmt.Errorf("%w: invalid bot image reference, it is nil", errInvalidBot)
	}

	image, err := utils.ValidateDiscoImageRef(
		cfg.Registry.ContainerRegistry, *signedManifest.Manifest.ImageReference,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid bot image reference '%s': %v", errInvalidBot, *signedManifest.Manifest.ImageReference, err)
	}

	return &config.AgentConfig{
		ID:              agentID,
		Image:           image,
		Manifest:        ref,
		ChainID:         cfg.ChainID,
		Owner:           owner,
		ProtocolVersion: signedManifest.Manifest.ProtocolVersion,
	}, signedManifest, nil
}

func (rs *registryStore) loadAssignment(assignment *registry.Assignment) (*config.AgentConfig, error) {
	botCfg, agentData, err := loadBot(rs.ctx, rs.cfg, rs.bms, assignment.AgentID, assignment.AgentManifest, assignment.AgentOwner)
	if err != nil {
		return nil, err
	}

	botCfg.Owner = assignment.AgentOwner

	if botCfg.ProtocolVersion >= 2 {
		var ok bool
		botCfg.ShardConfig, ok = sharding.CalculateShardConfigV2(assignment, agentData)
		if !ok {
			return nil, fmt.Errorf("%w: invalid sharding config", errInvalidBot)
		}
		botCfg.ChainID = int(botCfg.ShardConfig.ChainID)
	} else {
		botCfg.ShardConfig = sharding.CalculateShardConfig(assignment, agentData, rs.cfg.ChainID)
	}

	return botCfg, nil
}

func NewRegistryStore(ctx context.Context, cfg config.Config) (*registryStore, error) {
	mc, err := manifest.NewClient(cfg.Registry.IPFS.GatewayURL)
	if err != nil {
		return nil, err
	}
	bms := NewBotManifestStore(mc)

	rc, err := GetRegistryClient(
		ctx, cfg, registry.ClientConfig{
			JsonRpcUrl:       cfg.Registry.JsonRpc.Url,
			ENSAddress:       cfg.ENSConfig.ContractAddress,
			Name:             "registry-store",
			MulticallAddress: cfg.AdvancedConfig.MulticallAddress,
		},
	)
	if err != nil {
		return nil, err
	}

	// make sure the registry client is refreshed and in sync.
	go func() {
		ticker := time.NewTicker(time.Minute * 15)
		for {
			select {
			case <-ticker.C:
				err := rc.RefreshContracts()
				if err != nil {
					log.WithError(err).Warn("error while refreshing the registry contracts")
				}

			case <-ctx.Done():
				return
			}
		}
	}()

	return &registryStore{
		ctx: ctx,
		cfg: cfg,
		bms: bms,
		rc:  rc,
	}, nil
}

type privateRegistryStore struct {
	ctx context.Context
	cfg config.Config
	rc  registry.Client
	bms BotManifestStore
	mu  sync.Mutex
}

func (rs *privateRegistryStore) GetAgentsIfChanged(scanner string) ([]config.AgentConfig, bool, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()

	var agentConfigs []config.AgentConfig

	// load by image references
	for i, agentImage := range rs.cfg.LocalModeConfig.BotImages {
		if len(agentImage) == 0 {
			continue
		}
		// forta-agent-1, forta-agent-2, forta-agent-3, ...
		agentID := strconv.Itoa(i + 1)
		agentConfigs = append(agentConfigs, *rs.makePrivateModeAgentConfig(agentID, agentImage, nil))
	}

	// load by bot IDs
	for _, agentID := range rs.cfg.LocalModeConfig.BotIDs {
		agt, err := rs.rc.GetAgent(agentID)
		logger := log.WithFields(log.Fields{
			"botID": agentID,
		})
		if err != nil {
			logger.WithError(err).Error("failed to get bot from registry")
			continue
		}
		agtCfg, _, err := loadBot(rs.ctx, rs.cfg, rs.bms, agentID, agt.Manifest, agt.Owner)
		if err != nil {
			logger.WithError(err).Error("failed to load bot")
			continue
		}

		agtCfg.Owner = agt.Owner
		agentConfigs = append(agentConfigs, *agtCfg)
	}

	// load sharded bots by image
	for i, shardedBot := range rs.cfg.LocalModeConfig.ShardedBots {
		// load bot by image
		if shardedBot.BotImage != nil {
			instances := shardedBot.Shards * shardedBot.Target
			for botIdx := uint(0); botIdx < instances; botIdx++ {
				shardConfig := &config.ShardConfig{
					Shards:  shardedBot.Shards,
					Target:  shardedBot.Target,
					ShardID: sharding.CalculateShardID(shardedBot.Target, botIdx),
				}

				agentID := strconv.Itoa(len(agentConfigs) + i + 1)
				agentConfigs = append(
					agentConfigs, *rs.makePrivateModeAgentConfig(agentID, *shardedBot.BotImage, shardConfig),
				)
			}
		}
	}

	// load the standalone bot configs that are already running
	if rs.cfg.LocalModeConfig.IsStandalone() {
		for _, runningBot := range rs.cfg.LocalModeConfig.Standalone.BotContainers {
			agentConfigs = append(agentConfigs, config.AgentConfig{
				ID:           runningBot,
				IsStandalone: true,
				ChainID:      rs.cfg.ChainID,
			})
		}
	}

	return agentConfigs, true, nil
}

func (rs *privateRegistryStore) FindAgentGlobally(agentID string) (*config.AgentConfig, error) {
	return nil, ErrLocalMode
}

func (rs *privateRegistryStore) makePrivateModeAgentConfig(
	id string, image string,
	shardConfig *config.ShardConfig,
) *config.AgentConfig {
	return &config.AgentConfig{
		ID:          id,
		Image:       image,
		IsLocal:     true,
		ShardConfig: shardConfig,
		ChainID:     rs.cfg.ChainID,
	}
}

func NewPrivateRegistryStore(ctx context.Context, cfg config.Config) (*privateRegistryStore, error) {
	mc, err := manifest.NewClient(cfg.Registry.IPFS.GatewayURL)
	if err != nil {
		return nil, err
	}
	bms := NewBotManifestStore(mc)

	rc, err := GetRegistryClient(ctx, cfg, registry.ClientConfig{
		JsonRpcUrl: cfg.Registry.JsonRpc.Url,
		ENSAddress: cfg.ENSConfig.ContractAddress,
		Name:       "registry-store",
		NoRefresh:  cfg.LocalModeConfig.IsStandalone(),
	})
	if err != nil {
		return nil, err
	}
	return &privateRegistryStore{
		ctx: ctx,
		cfg: cfg,
		bms: bms,
		rc:  rc,
	}, nil
}

// GetRegistryClient checks the config and returns the suitaable registry.
func GetRegistryClient(ctx context.Context, cfg config.Config, registryClientCfg registry.ClientConfig) (registry.Client, error) {
	if cfg.ENSConfig.Override {
		ensResolver, err := NewENSOverrideResolver(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create ens override resolver: %v", err)
		}
		ensStore := ens.NewENStoreWithResolver(ensResolver)
		return registry.NewClientWithENSStore(ctx, registryClientCfg, ensStore)
	}
	return registry.NewClient(ctx, registryClientCfg)
}
