[⌂ Documentation](../README.md) › Proxy

# Le proxy Vaultaire

Un **proxy** est un nœud du cluster placé près des agents d'un site. Il
**transporte** leurs connexions vers les cores, sans les lire. Ce dossier
réunit ce qu'il faut pour le déployer, le régler et le dépanner.

```
  agents du site ──TCP──▶  vlt-proxy  ──TCP──▶  core 1
                             (relais)   └────▶  core 2   (repli, dans l'ordre)
```

| Page | Pour qui | Contenu |
|---|---|---|
| [`deploiement.md`](./deploiement.md) | exploitant | Enrôlement, conteneur `vlt-proxy`, `-listen-port`, `cluster expose`, dev-comp |
| [`relais.md`](./relais.md) | exploitant | Ce qu'est un relais, types, sources de cibles, section `relais:`, limites, journal |
| [`securite.md`](./securite.md) | exploitant, relecteur | Pourquoi le proxy ne déchiffre rien, ce que l'agent lui accorde, exemption côté core |
| [`prevu-https-ldap.md`](./prevu-https-ldap.md) | développeur | Relais HTTPS (vers les Nexus), LDAP et LDAPS : ce qui est prêt, ce qui manque (TO-DO 72) |
| [`depannage.md`](./depannage.md) | exploitant | Messages du journal, causes, vérifications |

## En une minute

- **Ce qui marche en 2.2** : le relais **Ducky** (agents → cores). C'est le lot 4
  du point 38.
- **Ce qui est prévu** : relais **HTTPS** vers des services du cluster (Nexus,
  par exemple), **LDAP** et **LDAPS** vers les cores. La configuration les
  reconnaît déjà ; le proxy refuse de les démarrer tant qu'ils ne sont pas
  activés (TO-DO 72).
- **Le proxy ne termine rien** : ni la session Ducky, ni TLS. Il ne voit jamais un
  mot de passe en clair.
- **Tous les cores injoignables → refus franc** : la connexion de l'agent est
  fermée aussitôt, et l'agent passe au nœud suivant de sa liste.
- **Un agent n'accorde aucune confiance au proxy** : il vérifie la clé du core
  au bout du tunnel, comme en direct.

## Le proxy dans le reste de la documentation

| Où | Quoi |
|---|---|
| [`training/10-cluster-et-proxy/`](../training/10-cluster-et-proxy/README.md) | Le chapitre de formation : clés d'enrôlement, déployer un proxy, topologie |
| [`Utilisation/MAN.md`](../Utilisation/MAN.md) | `vlt cluster` (list, expose, priority, rotation, affinity) et `vlt enroll` |
| [`ducky-network/04-cluster/`](../Developement/how%20it%20work/ducky-network/04-cluster/README.md) | La spécification : trames `04_*`, découverte, arbitrages |
| [`../../deployments/pre-prod/vlt-proxy/`](../../deployments/pre-prod/vlt-proxy/README.md) | Le conteneur de préprod (release installée) |
| [`../../deployments/dev-comp/`](../../deployments/dev-comp/README.md) | La pile compilée depuis le dépôt, proxy compris (`--proxy`) |
| [`exploitation/Agent_configuration_et_debug.md`](../exploitation/Agent_configuration_et_debug.md) | La liste des nœuds de l'agent et le rapport de debug |
