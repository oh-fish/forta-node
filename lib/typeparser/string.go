package typeparser

import (
	"os"
	"strings"
)

// IsIgnoreValue Ignore value like 0/none/null/nil
func IsIgnoreValue(str string) bool {
	if len(str) < 1 {
		return true
	}

	switch strings.ToLower(str) {
	case "0", "none", "null", "nil":
		return true
	case "auto", "undef":
		return true
	default:
		return false
	}
}

func EnvGetString(key string, dVal string) string {
	if val, has := os.LookupEnv(key); has == false {
		return dVal
	} else {
		return val
	}
}
