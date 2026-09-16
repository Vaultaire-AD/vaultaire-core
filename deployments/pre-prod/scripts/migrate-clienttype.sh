#!/bin/sh
# Migration du catalogue des types de clients.
#
#   docker exec -i vaultaire-db sh < deployments/pre-prod/scripts/migrate-clienttype.sh
#
# Contexte complet : docs/migrations/clienttype_catalogue.md
#
# ── Ce que fait ce script ─────────────────────────────────────────────────────
#
# id_logiciels.logiciel_type était un VARCHAR libre. Le catalogue
# (core/clienttype) en fait une frontière de privilège, fail-closed : un type
# absent du catalogue n'émet RIEN, donc la machine ne se connecte plus.
#
# Toute valeur hors catalogue désigne un AGENT : avant le catalogue, seuls les
# agents existaient. Les services ne peuvent être créés que par l'enrôlement,
# qui écrit lui-même une valeur valide.
#
# ── Il affiche AVANT d'écrire ─────────────────────────────────────────────────
#
# Une migration qui bascule des lignes sans les montrer laisse son auteur
# découvrir après coup qu'un service a été traité comme un agent — donc doté des
# catégories GPO, SSH et révocations, qui n'ont aucun sens pour lui.
#
# Passez APPLY=1 pour écrire. Sans cette variable, le script ne fait que lire.
set -e

DB="${MARIADB_DATABASE:-vaultaire}"
PASS="${MARIADB_ROOT_PASSWORD:-root}"
SQL="mariadb --protocol=socket -uroot -p${PASS} ${DB}"

command -v mariadb >/dev/null 2>&1 || SQL="mysql --protocol=socket -uroot -p${PASS} ${DB}"

echo "=== Répartition actuelle des types ==="
$SQL -t <<'EOSQL'
SELECT logiciel_type, COUNT(*) AS clients
  FROM id_logiciels
 GROUP BY logiciel_type
 ORDER BY clients DESC;
EOSQL

echo
echo "=== Lignes qui seront migrées vers vaultaire_client ==="
echo "    (vérifiez qu'aucune n'est un service : proxy ou interface web)"
$SQL -t <<'EOSQL'
SELECT computeur_id, logiciel_type, hostname, serveur
  FROM id_logiciels
 WHERE logiciel_type NOT IN ('vaultaire_client', 'vaultaire_proxy', 'vaultaire_web');
EOSQL

if [ "$APPLY" != "1" ]; then
    echo
    echo "Lecture seule. Pour appliquer :"
    echo "  docker exec -i -e APPLY=1 vaultaire-db sh < deployments/pre-prod/scripts/migrate-clienttype.sh"
    exit 0
fi

echo
echo "=== Migration ==="
$SQL <<'EOSQL'
UPDATE id_logiciels
   SET logiciel_type = 'vaultaire_client'
 WHERE logiciel_type NOT IN ('vaultaire_client', 'vaultaire_proxy', 'vaultaire_web');
EOSQL

echo "=== Répartition après migration ==="
$SQL -t <<'EOSQL'
SELECT logiciel_type, COUNT(*) AS clients
  FROM id_logiciels
 GROUP BY logiciel_type
 ORDER BY clients DESC;
EOSQL

echo
echo "Terminé. Redémarrez les agents concernés, ou attendez leur reconnexion."
