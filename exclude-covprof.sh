#!/bin/bash

if [ "$#" -ne 2 ]; then
    exit 1
fi

file1="$1"
file2="$2"

if [ ! -f "$file1" ] || [ ! -f "$file2" ]; then
    exit 1
fi

# Create a temporary file to store the result
temp_file=$(mktemp)

# Use grep to find lines in file1 that do not match any line in file2
grep -v -F -f "$file2" "$file1" > "$temp_file"

# Replace file1 with the contents of the temporary file
mv "$temp_file" "$file1"

