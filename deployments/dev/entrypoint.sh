#!/bin/bash
# Start rsyslog
# Arrêt à la première erreur.
#
#   -e            une commande qui échoue interrompt le script
#   -u            une variable non définie est une erreur, pas une chaîne vide
#   -o pipefail   un échec au milieu d'un tuyau n'est pas masqué par le succès
#                 de la dernière commande
#
# Sans -e, un script de déploiement poursuit après une étape ratée et rend 0 :
# la copie continue avec des binaires non compilés, le conteneur redémarre sur
# l'ancienne version, et rien ne le signale.
set -euo pipefail

/usr/sbin/rsyslogd

# Start SSH in foreground
exec /usr/sbin/sshd -D