# Rotation des journaux Vaultaire

Trois fichiers, un par entité, à copier dans `/etc/logrotate.d/` sur la machine
qui héberge l'entité correspondante.

| Fichier | Entité | Journaux | Taille max |
|---|---|---|---|
| `vaultaire-core` | core | `date.log`, `SQL_Injection.log` | 50 Mo |
| `vaultaire-client` | agent | `vaultaire_client.log` | 20 Mo |
| `vaultaire-proxy` | proxy | `vaultaire_proxy.log` | 100 Mo |

Politique commune : **un fichier par jour, 30 archives, compressées sauf la plus
récente.** Un mois glissant.

```bash
sudo cp deployments/logrotate/vaultaire-client /etc/logrotate.d/
sudo logrotate --debug /etc/logrotate.d/vaultaire-client   # simulation
```

## Le journal principal du core n'est pas ici

Le core écrit sur la sortie standard, et c'est systemd, journald ou le moteur de
conteneurs qui le collecte, avec sa propre rétention. Le faire tourner ici
reviendrait à en tenir deux, et « où sont les journaux » aurait deux réponses.

Seules deux familles passent par un fichier, parce qu'on veut pouvoir les lire
séparément du flot général : les dates de naissance refusées et les identifiants
écartés par l'assainissement des requêtes.

## `maxsize` demande un minuteur plus fréquent que quotidien

C'est le point le plus facile à manquer, et il annule discrètement la moitié de
la protection.

`daily` fait tourner au premier passage d'un nouveau jour. `maxsize` fait tourner
dès que le seuil est atteint — mais **seulement lors d'un passage**. Avec le
minuteur systemd standard, qui est quotidien, `maxsize` ne peut donc rien
déclencher que `daily` n'aurait pas déjà fait.

Or c'est précisément le cas qu'il couvre : un incident bavard qui remplit la
partition avant minuit. Pour qu'il serve, il faut invoquer logrotate plus
souvent :

```bash
sudo systemctl edit logrotate.timer
```

```ini
[Timer]
OnCalendar=
OnCalendar=hourly
```

Sans cela, gardez les fichiers tels quels — ils restent corrects — mais sachez
que la seule borne réelle est la cadence quotidienne.

## Pourquoi aucune ligne de code de rotation

Les trois programmes rouvrent leur fichier **par son chemin à chaque ligne**.
Après le renommage que fait logrotate, la ligne suivante recrée le fichier.

Ni `copytruncate` — qui perd les lignes écrites pendant la copie — ni signal de
réouverture, ni redémarrage de service.

C'est une propriété du code, pas un hasard, et elle est gardée par un test dans
chacun des deux paquets de journalisation. Elle se détruirait en une ligne, le
jour où quelqu'un garderait le descripteur ouvert pour économiser deux appels
système. Le symptôme serait un journal qui **s'arrête net après la première
rotation**, sans aucune erreur : le programme écrirait dans l'archive.

Si ce choix change un jour, il faut passer à `copytruncate` ou implémenter la
réouverture sur `SIGHUP` **dans le même geste**.

## Droits des fichiers

`create 0600 root root`. Ces journaux nomment des comptes, des machines, des
motifs de refus d'authentification et des tentatives d'injection.

Ils étaient créés en `0644` : tout utilisateur de la machine pouvait lire les
tentatives de connexion des autres. Le répertoire passe de `0755` à `0700` pour
la même raison.

## Un ancien répertoire à nettoyer

Une version antérieure du socle écrivait certaines familles dans
`/var/log/vaultaire_client/`, en dur, alors que le journal principal va dans
`/var/log/vaultaire/`. Ce second répertoire naissait au vol en `0755` et aucune
rotation ne le couvrait.

Les deux fonctions résolvent maintenant le même répertoire. Sur une machine
déployée avant ce changement :

```bash
ls -la /var/log/vaultaire_client/    # vérifier ce qu'il contient
sudo rm -rf /var/log/vaultaire_client/
```

Rien n'y est écrit par une version à jour.
