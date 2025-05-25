#!/bin/sh
# Implementation of assignment 1 item 9
# Author: Hatem Alamir
# Date: 12/11/2024

# Treat undefined variables as errors
set -u

if [ $# -lt 2 ]
then
    echo
    echo "Missing arguments! Expected:"
    echo "  1) Path to a directory on the filesystem to search in."
    echo "  2) Text string which will be searched within that directory."
    echo
    exit 1
fi

filesdir=$1
if [ ! -d "$filesdir" ]
then
    echo
    echo "Invalid arguments! First argument needs to be an existing directory."
    echo
    exit 1
fi
searchstr=$2

# -c: num of matching lines, -l num of matching files
matchfiles=$(grep -l -r "$searchstr" "$filesdir" | wc -l)
matchlines=$(grep -c -h -r "$searchstr" "$filesdir" | awk '{sum += $1} END {print sum}')

echo
echo "The number of files are $matchfiles and the number of matching lines are $matchlines"
echo
