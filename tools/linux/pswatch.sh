#!/bin/bash

# Watches for new processes to show up. Useful for catching cronjobs in action.

PS_CMD="ps -eo pid,ppid,pgrp,session,tty,user,args"
PS_FILTER="grep -v '"$PS_CMD"' | grep -v '"\\[$(basename $0)\\]"' | grep -v '"$0"' | grep -v grep"
PS="$PS_CMD | $PS_FILTER"

old="$(eval $PS)"

while true; do
    new="$(eval $PS)"
    diff="$(diff -a --suppress-common-lines <(echo "${old}") <(echo "${new}") | grep '[\<\>]')"
    if [ -n "$diff" ]; then
        echo "$(date '+%Y%m%d-%T') ============================================"
        echo "$diff"
        echo
    fi
    old="$new"
done