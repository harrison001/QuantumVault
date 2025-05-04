#!/bin/bash
# Cleanup script to remove unnecessary files

echo "Cleaning up unnecessary files..."

# Keep only essential files
KEEP_FILES=(
    "aes.c"
    "aes.h"
    "combined_decrypt.c"
    "Makefile"
    "README.md"
    "cleanup.sh"
)

# Delete everything except the files to keep
for file in *; do
    if [[ ! " ${KEEP_FILES[@]} " =~ " ${file} " ]]; then
        echo "Removing: $file"
        rm -f "$file"
    fi
done

# Remove any additional object and executable files
rm -f *.o *.exe

echo "Cleanup complete!"
echo "The folder now contains only the essential files for the DOS AES Decryption Tool." 