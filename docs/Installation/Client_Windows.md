[⌂ Documentation](../README.md) › [Installation](./Setup.md) › Poste Windows

# Installer l'agent Vaultaire sur un poste Windows (V1)

Authentifier un utilisateur du domaine sur un poste Windows, par mot de passe.
C'est tout ce que fait la V1 — et c'est déjà la porte d'entrée d'une machine,
donc à déployer avec les précautions de cette page.

---

## Ce qui marche, et ce qui ne marche pas encore

| | |
|---|---|
| ✅ | connexion d'un compte du domaine à l'écran de connexion Windows |
| ✅ | compte Windows local créé et tenu à jour par l'agent (mot de passe, groupes) |
| ✅ | la machine apparaît dans `vlt status -c`, déclare sa version, apprend ses cores et proxies |
| ✅ | **inventaire** : système, version commerciale et build, mémoire, processeurs, sessions ouvertes |
| ⏸ | **GPO** : reçues, journalisées, **jamais appliquées** |
| ⏸ | **révocations** : un compte révoqué ne pourra plus s'authentifier, mais sa session ouverte n'est pas fermée et son mot de passe local reste valable |
| ⏸ | **fin de session** : le poste ne prévient pas le core d'une déconnexion (trame `03_11`), donc `vlt status -u` garde la session affichée jusqu'à l'extinction du poste |
| ❌ | second facteur, changement de mot de passe depuis l'écran de connexion, SSH |

## Les deux composants

```
   écran de connexion (LogonUI.exe)
     └── VaultaireCredentialProvider.dll        tuile « Vaultaire »
            │  tube nommé, réservé à SYSTEM et aux administrateurs
            ▼
     vaultaire_client_windows.exe               service, compte SYSTEM
            │  tunnel Ducky
            ▼
          core
```

La DLL ne parle pas au réseau et ne détient aucune clé : elle pose une question
sur un tube et lit la réponse. Tout le reste vit dans le service. Ce découpage
existe parce qu'une DLL chargée par l'écran de connexion qui plante fait
disparaître l'écran de connexion de la machine.

## Avant de commencer

- un poste **Windows 10 / 11 ou Serveur 2019+**, 64 bits ;
- un **compte administrateur local**, et une session ouverte que vous garderez
  ouverte pendant l'essai ;
- le poste doit joindre un core ou un proxy sur le port **6666** ;
- l'archive `vaultaire-client-windows-<version>.tar`, produite par
  `src/vaultaire_client_windows/build.sh`.

## 1. Créer l'identité de la machine, sur le core

Un agent **ne s'enrôle pas seul** : seuls les services du cluster (proxy, Nexus)
le font avec une clé d'enrôlement. L'identité d'une machine est créée sur le
core, et transportée.

**Depuis le portail**, page *Clients* : choisissez « Windows » comme système,
créez la machine, et téléchargez l'archive proposée. Le lien ne sert **qu'une
fois** et expire en cinq minutes ; pour une machine déjà créée, le bouton
« Identité » de la liste en produit un nouveau.

**En ligne de commande**, si vous préférez :

```bash
vlt create -c non --os windows --export /tmp/poste01.zip
# pour une machine déjà créée :
vlt create -export <ID> /tmp/poste01.zip --os windows
```

L'archive contient tout ce dont l'agent a besoin :

| Fichier | À quoi il sert |
|---|---|
| `client_software.yaml` | l'identité : identifiant et type |
| `private_key.pem` | la **clé privée de la machine** |
| `core_key_fingerprint` | de quoi vérifier la clé du core au lieu de l'accepter sur parole |
| `client_conf.json` | les cores à joindre, tels que le cluster les expose |
| `LISEZ-MOI.txt` | ce que contient l'archive, et ce qui manque le cas échéant |

> ⚠️ **Elle contient une clé privée.** Elle vaut l'identité de la machine sur le
> parc : qui la détient peut se faire passer pour elle. Ne la laissez pas dans un
> dossier de téléchargement, et effacez-la une fois l'agent installé.

Il n'y a plus d'empreinte à relever ni à retaper : elle voyage dans l'archive.
Si le core n'a pas su la produire — cluster en cours de démarrage, par exemple —
le `LISEZ-MOI.txt` de l'archive le dit, et `install.ps1` repose alors la
question.

## 2. Installer sur le poste

Invite PowerShell **administrateur**, dans le dossier décompressé :

```powershell
.\install.ps1 -Identite C:\Users\...\Downloads\vaultaire-<ID>-windows.zip
```

`-Identite` accepte **l'archive `.zip` directement** — pas besoin de la
décompresser d'abord. Elle est extraite dans un dossier temporaire, effacé en fin
de script : une clé privée décompressée n'a rien à faire dans le dossier des
téléchargements. Un dossier déjà décompressé est accepté aussi.

Le script demande alors seulement s'il faut installer le service, et s'il faut
enregistrer la tuile de l'écran de connexion. L'identité, l'empreinte du core et
la liste des cores viennent de l'archive — les trois questions qu'il posait
auparavant ont disparu. Il ferme aussi `C:\ProgramData\Vaultaire` à tout le
monde sauf SYSTEM et les administrateurs.

Sans `-Identite`, il demande le chemin de l'archive.

**Répondez NON à la tuile au premier passage.** On vérifie d'abord que
l'authentification fonctionne.

## 3. Vérifier AVANT de toucher à l'écran de connexion

```powershell
cd C:\ProgramData\Vaultaire\bin
.\vaultaire_login.exe -etat                      # raccordé au domaine ?
.\vaultaire_login.exe -u alice@test.fr -check    # vérifie SANS créer de compte
.\vaultaire_login.exe -u alice@test.fr           # vérifie ET provisionne
```

`vaultaire_login` fait exactement ce que fera la tuile : même tube, mêmes
messages. Sur le core, `vlt status -c` doit montrer la machine.

| Réponse | Ce que cela veut dire |
|---|---|
| `success` + `compte local` | tout est en place ; ce compte local ouvrira la session |
| `failed` | le core a refusé — droit d'accès à la machine, domaine, mot de passe (le motif est dans le journal du **core**) |
| `unavailable` | aucun core joignable : pare-feu, adresse, service arrêté |
| `timeout` | le core n'a pas répondu à temps |

## 4. Activer la tuile

```powershell
.\install.ps1          # et cette fois, OUI à l'enregistrement
```

> ⚠️ **Gardez votre session administrateur ouverte** et vérifiez la connexion
> depuis une SECONDE session (verrouillage, ou changement d'utilisateur). Si la
> tuile pose problème :
>
> ```powershell
> .\uninstall.ps1 -CredentialProviderSeulement
> ```
>
> L'écran de connexion d'origine revient immédiatement ; l'agent continue de
> tourner.

L'identifiant se tape **`utilisateur@domaine`**. Sans domaine, la tuile refuse
en le disant : le domaine décide de ce que le core cherche.

## Le compte local, ce qu'il faut savoir

Windows n'ouvre de session qu'avec une identité qu'il connaît. L'agent crée donc
un compte **local** portant le mot de passe que le core vient de valider :

```
alice@test.fr   →   alice-1f4b2c
```

Le suffixe vient de l'empreinte de l'identifiant complet. Conséquences :

- le compte est **déterministe** : la même personne retrouve son profil ;
- deux domaines homonymes donnent deux comptes distincts ;
- un compte local préexistant (`alice`) n'est **jamais** repris ;
- le mot de passe local est réaligné à **chaque connexion réussie** ;
- un compte dont la personne ne se connecte plus garde son dernier mot de passe
  connu. La révocation empêche la prochaine authentification, pas l'usage d'un
  mot de passe déjà su.

La désinstallation **ne supprime pas** ces comptes : ils portent les profils.

## Où regarder quand ça ne va pas

| Fichier | Contenu |
|---|---|
| `C:\ProgramData\Vaultaire\logs\vaultaire_client_windows.log` | l'agent : tunnel, verdicts du core, provisionnement |
| `C:\ProgramData\Vaultaire\logs\credential_provider.log` | la tuile : ce qu'elle a demandé, ce que Windows a répondu |

| Symptôme | Cause probable |
|---|---|
| La tuile n'apparaît pas | DLL non enregistrée : `regsvr32 C:\ProgramData\Vaultaire\bin\VaultaireCredentialProvider.dll` |
| « Service Vaultaire arrêté sur ce poste » | `sc query VaultaireAgent` — le tube n'existe que si l'agent tourne |
| « Aucun serveur Vaultaire joignable » | pare-feu sortant, ou `servers` faux dans `client_conf.json` |
| Mot de passe accepté, Windows refuse la session | compte local non inscrit dans Utilisateurs, ou stratégie « Interdire l'ouverture de session locale » |
| « la politique de mot de passe de CE POSTE refuse… » (code 2245) | la politique locale est plus stricte que celle du domaine ; `install.ps1` propose de l'aligner, ou `secpol.msc` |
| Deux profils pour la même personne | l'identifiant a été tapé différemment : le nom local dépend du **nom complet** |

Détail technique, protocole du tube et compilation :
[`src/vaultaire_client_windows/README.md`](../../src/vaultaire_client_windows/README.md).
