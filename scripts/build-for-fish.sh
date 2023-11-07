#!/bin/bash

set -e
set -o pipefail

MODULE_NAME=$(grep 'module' go.mod | cut -c8-) # Get the module name from go.mod
IMPORT="$MODULE_NAME/config"
go build -o forta -ldflags="-X '$IMPORT.CommitHash=$1' -X '$IMPORT.Version=$2'" .