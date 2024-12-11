#!/bin/bash
# Implementation of assignment 1 item 10
# Author: Hatem Alamir
# Date: 12/11/2024

# Treat undefined variables as errors
set -u

if [ $# -lt 2 ]
then
    echo
    echo "Missing arguments! Expected:"
    echo "  1) Complete path to a file to write into."
    echo "  2) Text string to be written into that file."
    echo
    exit 1
fi

writefile=$1
dirpath=$(dirname "$writefile")
if [ ! -d "$dirpath" ]
then
    echo "Creating directory $dirpath"
    mkdir -p "$dirpath"
fi
touch "$writefile"
if [ $? -eq 0 ]
then
    echo "$writefile created successfully!"
else
    echo
    echo "Failed to create $writefile"
    echo
    exit 1
fi

echo "$2" > $writefile
if [ $? -eq 0 ]
then
    echo "Data written sucessfully to $writefile"
else
    echo "Failed to write to $writefile"
fi
