#!/bin/bash

file=$(hostname -I).txt
newfile=$(echo "$file" | tr -d ' ')
chmod +x ubuntu.sh
echo "Running....................."
./ubuntu.sh > $newfile 2>&1
echo "Done"
