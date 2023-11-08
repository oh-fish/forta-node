package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/forta-network/forta-core-go/clients/health"
	"github.com/forta-network/forta-core-go/utils"
	"github.com/forta-network/forta-node/config"
	"github.com/forta-network/forta-node/healthutils"
	"github.com/forta-network/forta-node/services"
	"github.com/forta-network/forta-node/services/updater"
	"github.com/forta-network/forta-node/store"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"path"
)

type keyAddress struct {
	Address string `json:"address"`
}

func loadAddressFromKeyFile() (string, error) {
	files, err := ioutil.ReadDir(config.DefaultContainerKeyDirPath)
	if err != nil {
		return "", err
	}

	if len(files) != 1 {
		return "", errors.New("there must be only one key in key directory")
	}

	b, err := ioutil.ReadFile(path.Join(config.DefaultContainerKeyDirPath, files[0].Name()))
	if err != nil {
		return "", err
	}

	var addr keyAddress
	if err := json.Unmarshal(b, &addr); err != nil {
		return "", err
	}

	return fmt.Sprintf("0x%s", addr.Address), nil
}

func initServices(ctx context.Context, cfg config.Config) ([]services.Service, error) {
	cfg.Registry.JsonRpc.Url = utils.ConvertToDockerHostURL(cfg.Registry.JsonRpc.Url)
	cfg.Registry.IPFS.APIURL = utils.ConvertToDockerHostURL(cfg.Registry.IPFS.APIURL)
	cfg.Registry.IPFS.GatewayURL = utils.ConvertToDockerHostURL(cfg.Registry.IPFS.GatewayURL)

	log.WithFields(log.Fields{
		"developmentMode": utils.ParseBoolEnvVar(config.EnvDevelopment),
	}).Info("updater modes")

	address, err := loadAddressFromKeyFile()
	if err != nil {
		return nil, err
	}

	srs, err := store.NewScannerReleaseStore(ctx, cfg)
	if err != nil {
		return nil, err
	}

	updaterService := updater.NewUpdaterService(
		ctx, srs, config.DefaultContainerPort, address, cfg.AutoUpdate.UpdateDelay, cfg.AutoUpdate.CheckIntervalSeconds,
	)

	return []services.Service{
		health.NewService(
			ctx, "", healthutils.DefaultHealthServerErrHandler,
			health.CheckerFrom(summarizeReports, updaterService),
		),
		updaterService,
	}, nil
}

func summarizeReports(reports health.Reports) *health.Report {
	summary := health.NewSummary()

	//checkedErr, ok := reports.NameContains("event.checked.error")
	//if !ok {
	//	summary.Fail()
	//	return summary.Finish()
	//}
	//if len(checkedErr.Details) > 0 {
	//	summary.Addf("auto-updater is failing to check new versions with error '%s'", checkedErr.Details)
	//	summary.Status(health.StatusFailing)
	//}
	//
	//checkedTime, ok := reports.NameContains("event.checked.time")
	//if ok {
	//	t, ok := checkedTime.Time()
	//	if ok {
	//		checkDelay := time.Since(*t)
	//		if checkDelay > time.Minute*10 {
	//			summary.Addf("and late for %d minutes", int64(checkDelay.Minutes()))
	//			summary.Status(health.StatusFailing)
	//		}
	//	}
	//}
	summary.Punc(".")
	return summary.Finish()
}

func Run() {
	services.ContainerMain("updater", initServices)
}
