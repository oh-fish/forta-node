package proc

import (
	"encoding/json"
	"fmt"
	"github.com/forta-network/forta-node/config"
	"os"
	"path"
	"strings"
)

// process info handler

type RunnerInfo struct {
	Pid   string `json:"pid"`
	Cid   string `json:"cid"`
	CName string `json:"c_name"`
}

func WriteRunnerInfo(baseDir string, name string, proc *RunnerInfo) error {
	procFile, err := GetRunnerFile(baseDir, name)
	if err != nil {
		return err
	}

	d, err := json.Marshal(proc)
	if err != nil {
		return err
	}

	err = os.WriteFile(procFile, d, 0644)
	if err != nil {
		return err
	}

	return nil
}

//func LoadRunnerInfo(baseDir string, name string) (RunnerInfo, error) {
//	procFile, err := GetRunnerFile(baseDir, name)
//	if err != nil {
//		return RunnerInfo{}, err
//	}
//
//	d, err := os.ReadFile(procFile)
//	if err != nil {
//		return RunnerInfo{}, err
//	}
//
//	var info RunnerInfo
//	err = json.Unmarshal(d, &info)
//	if err != nil {
//		return RunnerInfo{}, err
//	}
//
//	return info, nil
//}

func ClearRunnerInfo(baseDir string, name string) error {
	return WriteRunnerInfo(baseDir, name, &RunnerInfo{
		Pid:   "0",
		Cid:   "",
		CName: "",
	})
}

func _getRunnerDir(baseDir string) (string, error) {
	procDir := path.Join(baseDir, "runner_info")
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		err = os.Mkdir(procDir, 0644)
		if err != nil {
			return "", fmt.Errorf("failed to mkdir(%s): %s", procDir, err)
		}
	}

	return procDir, nil
}

func GetRunnerFile(baseDir string, name string) (string, error) {
	procDir, err := _getRunnerDir(baseDir)
	if err != nil {
		return "", fmt.Errorf("failed to get proc dir: %s", err)
	}

	return path.Join(procDir, name), nil
}

func _containerName2RunnerName(name string) (string, error) {
	ps := strings.SplitN(name, "-", 2)
	if len(ps) != 2 {
		return "", fmt.Errorf("invalid container name")
	}

	return ps[1], nil
}

func WriteRunnerInfoForContainer(cName string, info *RunnerInfo) error {
	name, err := _containerName2RunnerName(cName)
	if err != nil {
		return fmt.Errorf("failed to get proc name: %s", err)
	}

	return WriteRunnerInfo(config.DefaultContainerFortaDirPath, name, info)
}

func ClearRunnerInfoForContainer(cName string) error {
	name, err := _containerName2RunnerName(cName)
	if err != nil {
		return fmt.Errorf("failed to get proc name: %s", err)
	}

	return ClearRunnerInfo(config.DefaultContainerFortaDirPath, name)
}
