package config

import (
	"crypto/md5"
	"fmt"
	"path"
	"strconv"

	"github.com/forta-network/forta-core-go/utils"
	"github.com/forta-network/forta-node/lib/typeparser"
	log "github.com/sirupsen/logrus"
)

// InitFromEnv Init the global vars from the environment settings
func InitFromEnv() {
	// check and override the default port config
	DefaultNatsPort = typeparser.EnvGetString("FORTA_NATS_PORT", DefaultNatsPort)
	DefaultIPFSPort = typeparser.EnvGetString("FORTA_IPFS_PORT", DefaultIPFSPort)
	DefaultContainerPort = typeparser.EnvGetString("FORTA_CONTAINER_PORT", DefaultContainerPort)
	DefaultHealthPort = typeparser.EnvGetString("FORTA_HEALTH_PORT", DefaultHealthPort)
	DefaultJSONRPCProxyPort = typeparser.EnvGetString("FORTA_JSON_RPC_PROXY_PORT", DefaultJSONRPCProxyPort)
	//DefaultJWTProviderPort = typeparser.EnvGetString("FORTA_JWT_PROVIDER_PORT", DefaultJWTProviderPort)

	//DefaultPublicAPIProxyPort = GenDefaultPublicAPIProxyPort()
	DefaultBotHealthCheckPort = GenDefaultBotHealthCheckPort()

	DefaultFortaNodeBinaryPath = typeparser.EnvGetString("FORTA_NODE_BINARY_PATH", DefaultFortaNodeBinaryPath)

	// check and override the default containers config
	ContainerNamePrefix = typeparser.EnvGetString("CONTAINER_NAME_PREFIX", ContainerNamePrefix)
	DockerSupervisorImage = typeparser.EnvGetString("DOCKER_SUPERVISOR_IMAGE", DockerSupervisorImage)
	DockerUpdaterImage = typeparser.EnvGetString("DOCKER_UPDATER_IMAGE", DockerUpdaterImage)
	DockerClientNamePrefix = typeparser.EnvGetString("DOCKER_CLIENT_NAME_PREFIX", DockerClientNamePrefix)
	GlobalDockerClientName = typeparser.EnvGetString("GLOBAL_DOCKER_CLIENT_NAME", GlobalDockerClientName)

	DockerUpdaterContainerName = fmt.Sprintf("%s-updater", ContainerNamePrefix)
	DockerSupervisorContainerName = fmt.Sprintf("%s-supervisor", ContainerNamePrefix)
	DockerNatsContainerName = fmt.Sprintf("%s-nats", ContainerNamePrefix)
	DockerIpfsContainerName = fmt.Sprintf("%s-ipfs", ContainerNamePrefix)
	DockerScannerContainerName = fmt.Sprintf("%s-scanner", ContainerNamePrefix)
	DockerInspectorContainerName = fmt.Sprintf("%s-inspector", ContainerNamePrefix)
	DockerJSONRPCProxyContainerName = fmt.Sprintf("%s-json-rpc", ContainerNamePrefix)
	DockerPublicAPIProxyContainerName = fmt.Sprintf("%s-public-api", "forta")
	DockerJWTProviderContainerName = fmt.Sprintf("%s-jwt-provider", "forta")
	DockerStorageContainerName = fmt.Sprintf("%s-storage", ContainerNamePrefix)

	// dir path setting
	DefaultContainerFortaDirPath = typeparser.EnvGetString("CONTAINER_FORTA_DIR_PATH", DefaultContainerFortaDirPath)
	DefaultContainerConfigPath = path.Join(DefaultContainerFortaDirPath, DefaultConfigFileName)
	DefaultContainerWrappedConfigPath = path.Join(DefaultContainerFortaDirPath, DefaultWrappedConfigFileName)
	DefaultContainerKeyDirPath = path.Join(DefaultContainerFortaDirPath, DefaultKeysDirName)

	var logger = log.NewEntry(log.StandardLogger())
	logger.Debug("Default: ",
		"FORTA_NATS_PORT: ", DefaultNatsPort,
		", FORTA_IPFS_PORT: ", DefaultIPFSPort,
		", FORTA_CONTAINER_PORT: ", DefaultContainerPort,
		", FORTA_HEALTH_PORT: ", DefaultHealthPort,
		", FORTA_JSON_RPC_PROXY_PORT: ", DefaultJSONRPCProxyPort,
		", FORTA_JWT_PROVIDER_PORT: ", DefaultJWTProviderPort,
		", FORTA_NODE_BINARY_PATH: ", DefaultFortaNodeBinaryPath)
	logger.Debug("Container: ",
		"CONTAINER_NAME_PREFIX: ", ContainerNamePrefix,
		", DOCKER_CLIENT_NAME: ", DockerClientNamePrefix,
		", GLOBAL_DOCKER_CLIENT_NAME: ", GlobalDockerClientName,
		", UPDATER_CONTAINER_NAME: ", DockerUpdaterContainerName,
		", SUPERVISOR_CONTAINER_NAME: ", DockerSupervisorContainerName,
		", NATS_CONTAINER_NAME: ", DockerNatsContainerName,
		", IPFS_CONTAINER_NAME: ", DockerIpfsContainerName,
		", SCANNER_CONTAINER_NAME: ", DockerScannerContainerName,
		", INSPECTOR_CONTAINER_NAME: ", DockerInspectorContainerName,
		", JSON_PRC_CONTAINER_NAME: ", DockerJSONRPCProxyContainerName,
		", JTW_PROVIDER_CONTAINER_NAME: ", DockerJWTProviderContainerName)
}

func EnvBase(envs map[string]string) map[string]string {
	base := map[string]string{
		"FORTA_NATS_PORT":        DefaultNatsPort,
		"FORTA_IPFS_PORT":        DefaultIPFSPort,
		"FORTA_CONTAINER_PORT":   DefaultContainerPort,
		"FORTA_HEALTH_PORT":      DefaultHealthPort,
		EnvJsonRpcHost:           DockerJSONRPCProxyContainerName,
		EnvJsonRpcPort:           DefaultJSONRPCProxyPort,
		EnvJWTProviderHost:       DockerJWTProviderContainerName,
		EnvJWTProviderPort:       DefaultJWTProviderPort,
		EnvPublicAPIProxyHost:    DockerPublicAPIProxyContainerName,
		EnvPublicAPIProxyPort:    DefaultPublicAPIProxyPort,
		"FORTA_NODE_BINARY_PATH": DefaultFortaNodeBinaryPath,

		// check and override the default containers config
		"CONTAINER_NAME_PREFIX":     ContainerNamePrefix,
		"DOCKER_SUPERVISOR_IMAGE":   DockerSupervisorImage,
		"DOCKER_UPDATER_IMAGE":      DockerUpdaterImage,
		"DOCKER_CLIENT_NAME_PREFIX": DockerClientNamePrefix,
		"GLOBAL_DOCKER_CLIENT_NAME": GlobalDockerClientName,
		// dir path setting
		"CONTAINER_FORTA_DIR_PATH": DefaultContainerFortaDirPath,
	}

	if envs != nil {
		for k, v := range envs {
			base[k] = v
		}
	}

	return base
}

func GenPrometheusPort() int {
	num, err := strconv.Atoi(DefaultHealthPort)
	if err != nil {
		log.Error("gen prometheus port failed ")
	}
	port := num + 1001
	return port
}

func GenDefaultPublicAPIProxyPort() string {
	num, err := strconv.Atoi(DefaultContainerPort)
	if err != nil {
		log.Error("gen public api proxy port failed ")
	}
	port := num + 76
	return strconv.Itoa(port)

}

func GenDefaultAgentGrpcPort() string {
	num, err := strconv.Atoi(DefaultContainerPort)
	if err != nil {
		log.Error("gen agent grpc port failed ")
	}
	agentPort, err := strconv.Atoi(AgentGrpcPort)
	if err != nil {
		log.Error("gen int agentPort failed")
	}
	port := agentPort - num
	return strconv.Itoa(port)
}

func GenDefaultBotHealthCheckPort() string {
	num, err := strconv.Atoi(DefaultContainerPort)
	if err != nil {
		log.Error("gen agent grpc port failed ")
	}
	//agentPort, err := strconv.Atoi(AgentGrpcPort)
	//if err != nil {
	//	log.Error("gen int agentPort failed")
	//}
	port := num + 102
	return strconv.Itoa(port)
}

func GenPublicAgentNetworkName() string {
	b := []byte("forta" + ContainerNamePrefix)
	hasher := md5.New()
	hasher.Write(b)
	fortaNodeIdx := fmt.Sprintf("%x", hasher.Sum(nil))

	bc := []byte(ContainerNamePrefix)
	hasherH := md5.New()
	hasherH.Write(bc)
	fortaNodeIdxH := fmt.Sprintf("%x", hasherH.Sum(nil))
	return fmt.Sprint("forta-agent-%s-%s", utils.ShortenString(fortaNodeIdx, 8), utils.ShortenString(fortaNodeIdxH, 4))
}
