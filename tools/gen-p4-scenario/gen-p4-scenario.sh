#!/bin/bash

function print_usage_and_exit {
    echo "Usage: $0 [in_dir] [out_dir]"
    echo "       in_dir: P4 directory"
    echo "       out_dir: Scenario directory"
    exit
}

if [ $# -ne 2 ]; then
    print_usage_and_exit
fi

if [ ! -d $2 ]; then
    mkdir $2
fi

RULE_TAB='                    '
P4_FILE_NUM=`ls $1/*.proto | wc -l`
IDX=1

SCRIPT_DIR="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
ROOT_DIR=`git rev-parse --show-toplevel`
if [ $ROOT_DIR == "/" ]; then
    print_usage_and_exit
fi

DIFF_DIR=`realpath --relative-to=$ROOT_DIR $1`
echo $DIFF_DIR
for P4_PATH in $1/*
do
    P4_FILE=`basename $P4_PATH`

    if [[ $P4_FILE != *.proto ]]; then
        continue
    fi

    SCENARIO_FILE="$2/$P4_FILE.json"

    echo "[$IDX/$P4_FILE_NUM] $P4_FILE.json"

    echo "{" > $SCENARIO_FILE
    echo '    "name": "'$P4_FILE'",' >> $SCENARIO_FILE
    BEGIN_TEXT=`envsubst < $SCRIPT_DIR/begin.json`
    echo $BEGIN_TEXT >> $SCENARIO_FILE
    echo "$RULE_TAB\"ruleFilePath\": \"/$DIFF_DIR/$P4_FILE\"" >> $SCENARIO_FILE
    cat $SCRIPT_DIR/end.json >> $SCENARIO_FILE

    IDX=$(($IDX + 1))
done
