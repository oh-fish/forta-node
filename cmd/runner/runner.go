package runner

import (
	"context"
	"fmt"
	"github.com/forta-network/forta-node/services/proc"
	"os"

	"github.com/forta-network/forta-node/clients/docker"
	"github.com/forta-network/forta-node/config"
	"github.com/forta-network/forta-node/services"
	"github.com/forta-network/forta-node/services/runner"
	"github.com/forta-network/forta-node/store"
	log "github.com/sirupsen/logrus"
)

func initServices(ctx context.Context, cfg config.Config) ([]services.Service, error) {
	shouldDisableAutoUpdate := cfg.AutoUpdate.Disable
	imgStore, err := store.NewFortaImageStore(ctx, config.DefaultContainerPort, !shouldDisableAutoUpdate)
	if err != nil {
		return nil, fmt.Errorf("failed to create the image store: %v", err)
	}
	dockerClient, err := docker.NewDockerClient(fmt.Sprintf("%s_runner", config.DockerClientNamePrefix))
	if err != nil {
		return nil, fmt.Errorf("failed to create the docker client: %v", err)
	}
	globalDockerClient, err := docker.NewDockerClient(config.GlobalDockerClientName)
	if err != nil {
		return nil, fmt.Errorf("failed to create the docker client: %v", err)
	}

	if cfg.Development {
		log.Warn("running in development mode")
	}

	return []services.Service{
		runner.NewRunner(ctx, cfg, imgStore, dockerClient, globalDockerClient),
	}, nil
}

// Run runs the runner.
func Run(cfg config.Config) {
	ctx, cancel := services.InitMainContext()
	defer cancel()

	logger := log.WithField("process", "runner")
	logger.Info("starting")
	defer logger.Info("exiting")
	// get the forta dir
	fortaDir := os.Getenv("FORTA_DIR")
	if len(fortaDir) < 1 {
		logger.Errorf("FORTA_DIR is empty")
		return
	}
	if _, err := os.Stat(fortaDir); os.IsNotExist(err) {
		logger.Errorf("FORTA_DIR `%s` not exists", fortaDir)
		return
	}

	// mark 柒低个傻嘿进程既pid，方便我删柒佢
	err := proc.WriteRunnerInfo(fortaDir, config.DefaultRunnerProcName, &proc.RunnerInfo{
		Pid: fmt.Sprintf("%d", os.Getpid()),
	})
	if err != nil {
		logger.WithError(err).Error("failed to process info")
		return
	}
	defer func() {
		err = proc.ClearRunnerInfo(fortaDir, config.DefaultRunnerProcName)
		if err != nil {
			logger.WithError(err).Error("failed to clear proc info")
		}
	}()

	serviceList, err := initServices(ctx, cfg)
	if err != nil {
		logger.WithError(err).Error("could not initialize services")
		return
	}

	err = services.StartServices(ctx, cancel, log.NewEntry(log.StandardLogger()), serviceList)
	if err == services.ErrExitTriggered {
		logger.Info("exiting successfully after internal trigger")
		os.Exit(0)
	}
	if err != nil {
		logger.WithError(err).Error("error running services")
	}
}
