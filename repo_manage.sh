#!/usr/bin/env bash

set -e

PROTECTED_BRANCHES=("dev" "preprod" "main")

# Vérifie si on est dans un repo git
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "❌ Ce script doit être exécuté dans un dépôt Git."
    exit 1
fi

function create_branch() {
    echo "📦 Type de branche :"
    select branch_type in "feature" "hotfix" "experiment"; do
        [[ -n "$branch_type" ]] && break
    done

    read -rp "📝 Description (sans espaces, utilisez des -) : " description
    read -rp "🔢 Numéro d'issue : " issue

    branch_name="${branch_type}/${description}-${issue}"
    git checkout dev
    git pull origin dev
    git checkout -b "$branch_name"
    echo "✅ Branche '$branch_name' créée à partir de dev."
}
pull_request_branch() {
    local branch
    branch=$(git rev-parse --abbrev-ref HEAD)

    if [[ "$branch" == "HEAD" ]]; then
        echo "❌ You are in a detached HEAD state. Please checkout a branch first."
        return 1
    fi
    
    commit_changes

    echo "📜 Creating pull request for '$branch'..."
    gh pr create \
        --base dev \
        --head "$branch" \
        --title "$branch" \
        --body "Auto-created pull request for branch '$branch'."
}

function commit_changes() {
    echo "📦 Type de commit :"
    select commit_type in feat fix docs style refactor test chore; do
        [[ -n "$commit_type" ]] && break
    done

    read -rp "🎯 Scope (laisser vide si aucun) : " scope
    read -rp "📝 Description : " description

    if [[ -n "$scope" ]]; then
        message="${commit_type}(${scope}): ${description}"
    else
        message="${commit_type}: ${description}"
    fi

    git add .
    git commit -m "$message"
    git push
    echo "✅ Commit effectué : $message"
}

function delete_branch() {
    git fetch --all --prune
    echo "🗑 Branches locales disponibles :"
    git branch | grep -vE "^\*? (${PROTECTED_BRANCHES[*]// /|})"

    read -rp "🔹 Nom de la branche à supprimer : " branch_to_delete

    if [[ " ${PROTECTED_BRANCHES[*]} " =~ " ${branch_to_delete} " ]]; then
        echo "❌ Suppression interdite de la branche protégée '$branch_to_delete'."
        return
    fi

    git branch -d "$branch_to_delete" 2>/dev/null || git branch -D "$branch_to_delete"
    git push origin --delete "$branch_to_delete" || true
    echo "✅ Branche '$branch_to_delete' supprimée localement et sur le remote."
}

while true; do
    echo ""
    echo "===== 🚀 Git Manager ====="
    echo "(Assurez-vous d'être sur la branche à utiliser)"
    echo "1) Créer une branche"
    echo "2) Commit"
    echo "3) Crée une Pull Request"
    echo "4) Supprimer une branche"
    echo "5) Quitter"
    read -rp "Choisissez une option : " choice

    case "$choice" in
        1) create_branch ;;
        2) commit_changes ;;
        3) pull_request_branch ;;
        4) delete_branch ;;
        5) exit 0 ;;
        *) echo "❌ Option invalide" ;;
    esac
done
