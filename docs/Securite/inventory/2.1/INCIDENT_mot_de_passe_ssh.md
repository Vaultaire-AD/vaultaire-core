# Incident — un mot de passe refusé ouvrait la session SSH

**Corrigé.** Ce document dit quoi faire sur les machines déjà déployées.

## Ce qui se passait

Une connexion SSH aboutissait avec **n'importe quel mot de passe**, pour tout
compte du domaine autorisé sur la machine.

Le serveur central refusait correctement. C'est l'agent qui traduisait ce refus
en succès : le refus se signalait en fermant un canal interne, et le lecteur
prenait la valeur vide qui en sort pour une réponse valide.

## Portée

| | |
|---|---|
| **Touché** | l'authentification SSH par MOT DE PASSE, via l'agent Vaultaire |
| **Non touché** | le portail web, le bind LDAP, l'API, la trame `02_03` |
| **Non touché** | l'authentification SSH par CLÉ publique |
| **Depuis** | le 26 juillet 2026 — antérieur à la migration argon2 |

Le compte devait **exister dans l'annuaire** et **être autorisé sur la
machine** : le serveur vérifie cela avant le mot de passe, et ces refus-là
passaient par un autre chemin. Il ne s'agit donc pas d'un accès pour un inconnu,
mais d'un accès **sans connaître le mot de passe** pour qui sait un nom de
compte légitime.

## Ce qu'il faut faire

### 1. Déployer l'agent corrigé

C'est le seul geste indispensable. Tant qu'une machine porte l'ancien agent,
elle reste ouverte — le serveur, lui, n'a jamais eu besoin d'être corrigé.

```
./auto-compil.sh
# puis déploiement de vaultaire_client sur le parc
```

### 2. Vérifier ce que `/etc/shadow` contient

**C'est le point qu'on oublie.** À chaque connexion réussie, l'agent recopie le
mot de passe dans le `/etc/shadow` local, pour que `su`, la console et `sudo`
continuent de fonctionner hors ligne.

Une connexion aboutie avec un mauvais mot de passe a donc écrit **ce mauvais mot
de passe** localement. Il y reste jusqu'à la prochaine connexion réussie, qui le
resynchronise — et entre-temps, il ouvre `su`, la console et `sudo`.

La ligne à chercher dans le journal de l'agent :

```
Local password updated for <compte> (differed from central)
```

Sur un parc sain, elle apparaît **rarement** : seulement quand le mot de passe a
réellement changé côté annuaire. Une occurrence par connexion est le signe que
quelque chose n'allait pas.

Pour forcer la resynchronisation d'un compte sans attendre : une connexion SSH
réussie avec le bon mot de passe suffit. Pour couper court sur une machine :

```
passwd -l <compte>      # verrouille le mot de passe local
```

Le compte reste joignable par Vaultaire — l'agent le déverrouille à la prochaine
connexion validée.

### 3. Relire les journaux

Sur le **core**, les tentatives refusées sont tracées :

```
grep "SSH: mot de passe incorrect" <journal du core>
```

Chaque ligne est une tentative que le serveur a refusée — et que l'agent, avant
correction, laissait passer. Croisez les comptes et les machines qui y
apparaissent.

Sur les **agents**, la trace de la contradiction :

```
grep -A2 "Le serveur central a refusé l'accès SSH" <journal de l'agent>
```

Si la ligne suivante dit « Reponse du serveur central recue … (Admin: false,
Cles: 0) », la session a été ouverte malgré le refus.

## Ce qui empêche le retour du défaut

Le verdict d'authentification est désormais un champ **posé explicitement**,
faux par défaut, jamais déduit d'une absence d'information. Un chemin qui
oublierait de remplir la réponse refuse au lieu d'accepter.

Six tests couvrent la décision, dont un balayage exhaustif des vingt
combinaisons possibles : une seule est acceptée. Le premier rejoue exactement le
canal fermé qui a ouvert la porte.
