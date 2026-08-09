#!/usr/bin/env bash
# ====================================================================
# Tests du portail web — exécution locale, sans rien installer dans le
# système
# ====================================================================
#
# jsdom est la seule dépendance, et elle est installée DANS ce répertoire
# (node_modules/, ignoré par git). Le dépôt n'a pas de package.json à la
# racine et n'en veut pas : le portail est servi par Go, pas par npm.
#
#     ./run_tests.sh
#
# Sortie 0 si tout passe, 1 sinon. Le script s'arrête proprement, sans
# échouer, si Node n'est pas installé : ces tests ne doivent pas bloquer
# quelqu'un qui ne touche qu'au code Go.

set -u
cd "$(dirname "$0")"

if ! command -v node >/dev/null 2>&1; then
  echo "⏭️  Node absent — tests du portail web ignorés."
  exit 0
fi

if [ ! -d node_modules/jsdom ]; then
  if ! command -v npm >/dev/null 2>&1; then
    echo "⏭️  npm absent — impossible d'installer jsdom, tests ignorés."
    exit 0
  fi
  echo "📦 Installation de jsdom (une seule fois)…"
  npm install --silent --no-audit --no-fund --no-package-lock jsdom || {
    echo "❌ Installation de jsdom impossible."
    exit 1
  }
fi

echo "🧪 vlt_picker"
node vlt_picker.test.js
