package supervisor

import (
	"context"
	"fmt"
	"github.com/forta-network/forta-core-go/clients/health"
	"github.com/forta-network/forta-core-go/security"
	"github.com/forta-network/forta-core-go/utils"
	"github.com/forta-network/forta-node/config"
	"github.com/forta-network/forta-node/healthutils"
	"github.com/forta-network/forta-node/services"
	"github.com/forta-network/forta-node/services/components"
	"github.com/forta-network/forta-node/services/components/registry"
	"github.com/forta-network/forta-node/services/supervisor"
	log "github.com/sirupsen/logrus"
)

func initServices(ctx context.Context, cfg config.Config) ([]services.Service, error) {
	cfg.Registry.JsonRpc.Url = utils.ConvertToDockerHostURL(cfg.Registry.JsonRpc.Url)
	cfg.Registry.IPFS.APIURL = utils.ConvertToDockerHostURL(cfg.Registry.IPFS.APIURL)
	cfg.Registry.IPFS.GatewayURL = utils.ConvertToDockerHostURL(cfg.Registry.IPFS.GatewayURL)
	cfg.AgentLogsConfig.URL = utils.ConvertToDockerHostURL(cfg.AgentLogsConfig.URL)

	passphrase, err := security.ReadPassphrase()
	//config.DefaultFortaPassphrase

	log.Infof(" ---  ---- --- -- passphrase: %v", config.DefaultFortaPassphrase)

	if err != nil {
		return nil, err
	}
	key, err := security.LoadKey(config.DefaultContainerKeyDirPath)
	if err != nil {
		return nil, err
	}
	botRegistry, err := registry.New(cfg, key.Address)
	if err != nil {
		return nil, fmt.Errorf("failed to create the bot registry: %v", err)
	}
	botLifecycleConfig := components.BotLifecycleConfig{
		Config:         cfg,
		ScannerAddress: key.Address,
		BotRegistry:    botRegistry,
		Key:            key,
	}
	svc, err := supervisor.NewSupervisorService(ctx, supervisor.SupervisorServiceConfig{
		Config:             cfg,
		Passphrase:         passphrase,
		Key:                key,
		BotLifecycleConfig: botLifecycleConfig,
	})
	if err != nil {
		return nil, err
	}
	return []services.Service{
		health.NewService(
			ctx, "", healthutils.DefaultHealthServerErrHandler,
			health.CheckerFrom(summarizeReports, svc, botRegistry),
		),
		svc,
	}, nil
}

func summarizeReports(reports health.Reports) *health.Report {
	summary := health.NewSummary()
	//
	//containersManager, ok := reports.NameContains("containers.managed")
	//if ok {
	//	count, _ := strconv.Atoi(containersManager.Details)
	//	if count < config.DockerSupervisorManagedContainers {
	//		summary.Addf("missing %d containers.", config.DockerSupervisorManagedContainers-count)
	//		summary.Status(health.StatusFailing)
	//	} else {
	//		summary.Addf("all %d service containers are running.", config.DockerSupervisorManagedContainers)
	//	}
	//}
	//
	//telemetryErr, ok := reports.NameContains("telemetry-sync.error")
	//if ok && len(telemetryErr.Details) > 0 {
	//	summary.Addf("telemetry sync is failing with error '%s' (non-critical).", telemetryErr.Details)
	//	// do not change status - non critical
	//}

	return summary.Finish()
}

func Run() {
	services.ContainerMain("supervisor", initServices)
}
