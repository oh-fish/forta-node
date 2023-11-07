package typeparser

import (
	"fmt"
	"os"
	"strings"
)

func ToBool(val string) (bool, error) {
	switch strings.ToLower(val) {
	case "true", "1", "on", "yes":
		return true, nil
	case "false", "0", "off", "no":
		return false, nil
	default:
		return false, fmt.Errorf("invalid bool value '%s'", val)
	}
}

func EnvGetBool(key string, dVal bool) (bool, error) {
	if val, has := os.LookupEnv(key); has == false {
		return dVal, nil
	} else if b, err := ToBool(val); err != nil {
		return dVal, fmt.Errorf("invalid bool value for %s", key)
	} else {
		return b, nil
	}
}
