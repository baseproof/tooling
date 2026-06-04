#!/bin/bash

# Target file
FILE="LICENSE"

# The incorrect text you want to search for to identify the bad commit
SEARCH_TEXT="The Wrong License Name"

echo "Scanning Git history for the incorrect license..."

# Iterate through all commits from oldest to newest
for COMMIT in $(git rev-list --reverse HEAD); do
    # Check if the file exists in this commit
    if git ls-tree -r $COMMIT --name-only | grep -q "^$FILE$"; then
        # Check if the file contains the incorrect text
        if git show $COMMIT:$FILE | grep -q "$SEARCH_TEXT"; then
            echo "Incorrect license detected in commit: $COMMIT"
            
            # Get the parent commit to use as the base for our rebase
            PARENT_COMMIT=$(git rev-parse $COMMIT^)
            echo "You should rebase starting from: $PARENT_COMMIT"
            
            # Export for use in the next step
            export BAD_COMMIT=$COMMIT
            export REBASE_BASE=$PARENT_COMMIT
            break
        fi
    fi
done