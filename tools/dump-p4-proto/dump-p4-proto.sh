#!/bin/bash

function print_usage_and_exit {
    echo "Usage: $0 [errorCmd] [scenario-dir]"
    exit
}

if [ $# -ne 2 ]; then
    print_usage_and_exit
elif [ ! -d $2 ]; then
    print_usage_and_exit
fi

ROOT_DIR=`git rev-parse --show-toplevel`
SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
SCENARIO_DIR_NAME=`basename $2`
PROTO_DIR="$ROOT_DIR/scenarios/.intent"

grep -r $1 $2/failure | grep -Eo "/[0-9\-]*.proto" | xargs -I {} echo ".{}" | tar -cvf $SCENARIO_DIR_NAME-$1.tar -C $PROTO_DIR -T -
