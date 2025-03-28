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
TMP_FILE="/tmp/id_list.txt"
TMP_PROTO_LIST_FILE="/tmp/proto_list.txt"

grep -r $1 $2/failure | grep -Eo '"id":"[a-z0-9\-]*"' | sort | uniq -c | awk '{print $2}' > $TMP_FILE
rm $TMP_PROTO_LIST_FILE && touch $TMP_PROTO_LIST_FILE
while IFS= read -r line
do
    grep -r -m 1 $line $2/failure | grep -Eo "/[0-9\-]*.proto" | xargs -I {} echo ".{}" >> $TMP_PROTO_LIST_FILE
done < "$TMP_FILE"

tar -cvf $SCENARIO_DIR_NAME-$1.tar -C $PROTO_DIR -T $TMP_PROTO_LIST_FILE
