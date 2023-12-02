package provider

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/forta-network/forta-core-go/security"
	log "github.com/sirupsen/logrus"

	"github.com/forta-network/forta-node/clients"
	"github.com/forta-network/forta-node/clients/docker"
	"github.com/forta-network/forta-node/config"
	sec "github.com/forta-network/forta-node/services/components/security"
)

var ErrCannotFindBotForIP = errors.New("cannot find bot for ip")

type JWTProvider interface {
	CreateJWTFromIP(ctx context.Context, ipAddress string, claims map[string]interface{}) (string, error)
	SetScannerKeyDir(ctx context.Context, gatewayPrefix string, key *keystore.Key) (string, error)
	GetScannerMap(ctx context.Context) map[string]*keystore.Key
}

type jwtProvider struct {
	cfg            config.Config
	key            *keystore.Key
	dockerClient   clients.DockerClient
	jwtCreatorFunc func(key *keystore.Key, claims map[string]interface{}) (string, error)
	fishMap        map[string]*keystore.Key
}

func NewJWTProvider(cfg config.Config) (JWTProvider, error) {
	dc, err := docker.NewDockerClient("")
	if err != nil {
		return nil, fmt.Errorf("failed to create the global docker client: %v", err)
	}
	key, err := security.LoadKey(config.DefaultContainerKeyDirPath)
	if err != nil {
		return nil, err
	}
	return &jwtProvider{
		cfg:            cfg,
		key:            key,
		dockerClient:   dc,
		jwtCreatorFunc: security.CreateScannerJWT,
		fishMap:        map[string]*keystore.Key{},
	}, nil
}

func (p *jwtProvider) CreateJWTFromIP(ctx context.Context, ipAddress string, claims map[string]interface{}) (string, error) {
	logger := log.WithFields(log.Fields{
		"ip": ipAddress,
	})
	bot, err := p.getBotIDForIPAddress(ctx, ipAddress)
	if err != nil {
		logger.WithError(err).Warn("could not get bot by ip")
		return "", ErrCannotFindBotForIP
	}
	logger = logger.WithFields(log.Fields{
		"agentId": bot,
	})

	ipElms := strings.Split(ipAddress, ".")
	ipElms = ipElms[:len(ipElms)-1]
	gatewayPrefix := strings.Join(ipElms, ".")
	//fmt.Sprintf("%s", p.fishMap[gatewayPrefix])
	//
	//res, err := sec.CreateBotJWT(p.fishMap[gatewayPrefix], bot, claims, p.jwtCreatorFunc)
	for k, v := range p.GetScannerMap(ctx) {
		log.WithField("api", "handleJwtRequest").Infof("ScannerMap CacheElm - [%s] - [%s] - [%s] - [%s]", k, v, p.fishMap[gatewayPrefix], p.key)
	}
	res, err := sec.CreateBotJWT(p.key, bot, claims, p.jwtCreatorFunc)
	if err != nil {
		logger.WithError(err).Error("error creating jwt")
		return "", err
	}

	return res, nil
}

func (p *jwtProvider) SetScannerKeyDir(ctx context.Context, gatewayPrefix string, key *keystore.Key) (string, error) {
	p.fishMap[gatewayPrefix] = key
	return "", nil
}

func (p *jwtProvider) GetScannerMap(ctx context.Context) map[string]*keystore.Key {
	return p.fishMap
}

// agentIDReverseLookup reverse lookup from ip to agent id.
func (p *jwtProvider) getBotIDForIPAddress(ctx context.Context, ipAddr string) (string, error) {
	container, err := p.findContainerByIP(ctx, ipAddr)
	if err != nil {
		return "", err
	}

	botID, err := p.extractBotIDFromContainer(ctx, container)
	if err != nil {
		return "", err
	}

	return botID, nil
}

const envPrefix = config.EnvFortaBotID + "="

func (p *jwtProvider) extractBotIDFromContainer(ctx context.Context, container types.Container) (string, error) {
	// container struct doesn't have the "env" information, inspection required.
	c, err := p.dockerClient.InspectContainer(ctx, container.ID)
	if err != nil {
		return "", err
	}

	// find the env variable with bot id
	for _, s := range c.Config.Env {
		if env := strings.SplitAfter(s, envPrefix); len(env) == 2 {
			return env[1], nil
		}
	}

	return "", fmt.Errorf("can't extract bot id from container")
}

func (p *jwtProvider) findContainerByIP(ctx context.Context, ipAddr string) (types.Container, error) {
	containers, err := p.dockerClient.GetContainers(ctx)
	if err != nil {
		return types.Container{}, err
	}

	// find the container that has the same ip
	for _, container := range containers {
		for _, network := range container.NetworkSettings.Networks {
			if network.IPAddress == ipAddr {
				return container, nil
			}
		}
	}
	return types.Container{}, fmt.Errorf("can't find container %s", ipAddr)
}
