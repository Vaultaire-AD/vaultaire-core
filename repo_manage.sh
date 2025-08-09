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
    echo "✅ Commit effectué : $message"
}

function create_merge_request() {
    current_branch=$(git branch --show-current)
    if [[ " ${PROTECTED_BRANCHES[*]} " =~ " ${current_branch} " ]]; then
        echo "❌ Impossible de créer une MR depuis '${current_branch}'."
        return
    fi

    read -rp "📍 Cible de la MR (dev/main/preprod) : " target_branch
    if [[ ! " ${PROTECTED_BRANCHES[*]} " =~ " ${target_branch} " ]]; then
        echo "❌ Branche cible invalide."
        return
    fi

    git push -u origin "$current_branch"
    echo "🌐 Créez la MR sur votre interface GitLab/GitHub :"
    echo "   De '${current_branch}' vers '${target_branch}'"
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
    echo "1) Créer une branche"
    echo "2) Commit"
    echo "3) Créer une merge request"
    echo "4) Supprimer une branche"
    echo "5) Quitter"
    read -rp "Choisissez une option : " choice

    case "$choice" in
        1) create_branch ;;
        2) commit_changes ;;
        3) create_merge_request ;;
        4) delete_branch ;;
        5) exit 0 ;;
        *) echo "❌ Option invalide" ;;
    esac
done
