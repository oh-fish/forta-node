package typeparser

import (
	"fmt"
	"os"
	"strconv"
)

func EnvGetInt(key string, dVal int) (int, error) {
	if val, has := os.LookupEnv(key); has == false {
		return dVal, nil
	} else if i, err := strconv.Atoi(val); err != nil {
		return dVal, fmt.Errorf("invalid integer value for env var '%s'", key)
	} else {
		return i, nil
	}
}

func EnvGetUInt(key string, dVal uint64) (uint64, error) {
	if val, has := os.LookupEnv(key); has == false {
		return dVal, nil
	} else if i, err := strconv.ParseUint(val, 10, 64); err != nil {
		return dVal, fmt.Errorf("invalid integer value for env var '%s'", key)
	} else {
		return i, nil
	}
}
