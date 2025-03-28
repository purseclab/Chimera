#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 [host_num] [file]"
    exit
fi

OUTPUT_FILE=$2
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

HOSTS=`curl -X GET http://localhost:5000/topology -H "Content-Type: application/json" | jq -r '.topology.hosts | .[] | .mac '`

if [[ $1 -eq 0 ]]; then
    SRC_HOST="FE\\xFF\\xFF\\xFF\\xFF\\xFF"
else
    SRC_HOST=`echo $HOSTS | awk '{print $'$1'}' | sed 's/:/\\\\x/g'`
fi
DST_HOST=`echo $HOSTS | awk '{print $1}' | sed 's/:/\\\\x/g'`
echo "Host will be detected: \\x$SRC_HOST"

HOST_TAB='  '
IP_HEADER_LEN=21

cat $SCRIPT_DIR/begin.txt > $OUTPUT_FILE
echo -n "$HOST_TAB""packet: \"\\x7F\\x80\\x${DST_HOST}\\x${SRC_HOST}" >> $OUTPUT_FILE
echo -n "\\x08\\x00" >> $OUTPUT_FILE
for (( i=0; i<$IP_HEADER_LEN; i++ ))
do
    echo -n "\\x00" >> $OUTPUT_FILE
done
echo "\"" >> $OUTPUT_FILE

cat $SCRIPT_DIR/middle.txt >> $OUTPUT_FILE
echo -n "$HOST_TAB""packet: \"\\x7F\\x80\\x${DST_HOST}\\x${SRC_HOST}" >> $OUTPUT_FILE
echo -n "\\x08\\x00" >> $OUTPUT_FILE
for (( i=0; i<10; i++ ))
do
    echo -n "\\x00" >> $OUTPUT_FILE
done
echo -n "\\xFF\xFF" >> $OUTPUT_FILE
for (( i=12; i<$IP_HEADER_LEN; i++ ))
do
    echo -n "\\x00" >> $OUTPUT_FILE
done
echo "\"" >> $OUTPUT_FILE
cat $SCRIPT_DIR/end.txt >> $OUTPUT_FILE

