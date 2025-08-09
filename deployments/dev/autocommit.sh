#!/bin/bash

# Change ownership of all files and directories
sudo chown -R farkas ./*

# List all branches
echo "Fetching all branches..."
branches=$(git branch -r | sed 's/origin\///' | grep -v 'HEAD')
echo "Available branches:"
echo "$branches"

# Ask the user to select a branch
read -p "Enter the branch you want to push to: " selected_branch

# Check if the branch exists
if [[ ! $branches =~ $selected_branch ]]; then
    echo "Error: Branch '$selected_branch' does not exist."
    exit 1
fi

# Ask for the commit message
read -p "Enter your commit message: " commit_message

# Add, commit, and push the changes
git add .
git commit -m "$commit_message"
git push origin "$selected_branch"

echo "Changes have been pushed to branch '$selected_branch'."
