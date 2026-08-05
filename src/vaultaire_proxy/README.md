# vaultaire_proxy — version 1

Client **service** du cluster Vaultaire. Cette version établit et maintient la
présence du proxy dans le cluster ; la répartition de charge viendra ensuite.

## Ce qu'il fait

1. **S'enrôle** au premier démarrage avec la clé de sa configuration. Il génère
   sa paire RSA-4096 localement : **sa clé privée ne quitte jamais l'hôte**.
2. **Se connecte** au core et ouvre une session chiffrée.
3. **S'enregistre** dans le cluster et **bat** toutes les 45 secondes.
4. **Sort proprement** à l'arrêt, pour qu'un arrêt planifié ne ressemble pas à
   une panne.

## Installation

Émettre une clé sur le core :

```bash
vlt enroll create --type vaultaire_proxy --uses 1 --expires 30m
```

Copier `config.example.yaml` en `/etc/vaultaire_proxy/config.yaml`, y coller la
clé, puis démarrer. Le fichier de configuration ne contient **ni identifiant ni
clé privée** : le même peut être déployé sur plusieurs hôtes, chacun s'enrôlera
et obtiendra sa propre identité.

## Cycle de vie côté core

| Situation | Ce que fait le core |
|---|---|
| Bat régulièrement | `online` dans le cluster |
| Cesse de battre quelques minutes | `offline`, disparaît des vues, **identité conservée** |
| Ne revient pas avant le délai de purge | Ligne cluster **et client supprimés** |

Le délai se règle avec `vlt cluster purge-delay <heures>`, 24 h par défaut, 0
pour désactiver la purge.

Les deux étapes répondent à deux questions différentes. « Répond-il en ce
moment ? » se pose en minutes et n'a aucune conséquence. « Existe-t-il encore ? »
se pose en heures et détruit une identité — les confondre ferait d'une coupure
réseau de dix minutes la perte d'un enrôlement.

## Auto-réinitialisation

Si le core refuse l'identité du proxy — client purgé, clé publique remplacée —,
réessayer avec la même paire ne mènera jamais nulle part. Le proxy efface alors
son identité et se réenrôle avec la clé de sa configuration.

**C'est conditionné à ce seul cas.** Un core injoignable ou une coupure réseau ne
déclenchent PAS de réenrôlement : ils consommeraient une utilisation de clé à
chaque incident, et une clé à usage unique serait épuisée par la première panne.

Réinitialisation manuelle : `vaultaire_proxy --reset-identity`.

## Le protocole n'est pas ici

Aucune trame n'est implémentée dans ce dépôt. Poignée de main, enrôlement,
chiffrement, reconnexion et auto-réinitialisation vivent dans
`src/ducky-network-sdk`, commun à tous les clients.

C'est la propriété qui compte : quand le protocole est durci, le proxy en
bénéficie sans qu'une ligne n'y soit écrite. La version précédente portait sa
propre copie du protocole — elle était restée sur PKCS#1 v1.5 après la migration
du core vers OAEP, et **ne pouvait plus parler au core du tout**.
