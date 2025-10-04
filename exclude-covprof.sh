#!/bin/bash

# Script to filter coverage profile based on exclusion file

if [ $# -ne 2 ]; then
    echo "Usage: $0 <coverage_profile> <exclusion_file>"
    exit 1
fi

file1="$1"  # coverage profile
file2="$2"  # exclusion file

echo "DEBUG: Processing coverage file: $file1"
echo "DEBUG: Using exclusion config: $file2"

# Show initial stats
initial_lines=$(wc -l < "$file1")
echo "DEBUG: Initial coverage file has $initial_lines lines"

# Create temporary file for filtered output
temp_file=$(mktemp)

# Start with the mode line
head -1 "$file1" > "$temp_file"

# Get the coverage lines (skip mode line)
coverage_lines=$(mktemp)
tail -n +2 "$file1" > "$coverage_lines"

# Apply exclusions
while IFS= read -r exclusion || [[ -n "$exclusion" ]]; do
    # Skip comments and empty lines
    if [[ "$exclusion" =~ ^[[:space:]]*# ]] || [[ -z "${exclusion// }" ]]; then
        continue
    fi
    
    # Remove lines matching the exclusion pattern
    if [[ "$exclusion" == *":"*":"* ]]; then
        # Function exclusion format: file:line:func
        grep -v "^$exclusion" "$coverage_lines" > "${coverage_lines}.tmp" && mv "${coverage_lines}.tmp" "$coverage_lines"
    else
        # File exclusion - exclude entire file
        grep -v "^$exclusion:" "$coverage_lines" > "${coverage_lines}.tmp" && mv "${coverage_lines}.tmp" "$coverage_lines"
    fi
done < "$file2"

# Append filtered coverage to output
cat "$coverage_lines" >> "$temp_file"

# Clean up
rm -f "$coverage_lines"

# Show final stats
final_lines=$(wc -l < "$temp_file")
excluded_lines=$((initial_lines - final_lines))
echo "DEBUG: Final coverage file has $final_lines lines"
echo "DEBUG: Excluded $excluded_lines lines"

# Replace original file with filtered content
mv "$temp_file" "$file1"

echo "Exclusions applied to $file1"

