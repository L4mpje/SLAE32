#!/bin/bash
objdump -d $1 | grep '[0-9a-f]:' | grep -v 'file' | cut -d ':' -f 2 | cut -f1-6 -d ' ' | tr -s ' ' | tr '\t' ' ' | sed 's/ $//g' | sed 's/ /\\x/g' | paste -d '' -s | sed 's/^/"/' | sed 's/$/"/'
