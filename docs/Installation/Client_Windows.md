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

```bash
vlt create -c non
#   → Machine créée, identifiant <ID>
#   → <clientconfpath>/clientsoftware/<ID>/
#        client_software.yaml
#        private_key.pem
```

Copiez ce dossier sur le poste (partage, clé USB, `scp`). Il contient la **clé
privée de la machine** : traitez-le comme tel, et effacez la copie de transport.

Relevez aussi l'empreinte de la clé du core (`vlt certificate fingerprint`) :
sans elle, le poste fait confiance au premier serveur qui répond.

## 2. Installer sur le poste

Invite PowerShell **administrateur**, dans le dossier décompressé :

```powershell
.\install.ps1
```

Le script demande, dans l'ordre : le dossier d'identité, les cores joignables,
l'empreinte du core (facultative), s'il faut installer le service, et s'il faut
enregistrer la tuile de l'écran de connexion. Il ferme aussi
`C:\ProgramData\Vaultaire` à tout le monde sauf SYSTEM et les administrateurs.

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
| Deux profils pour la même personne | l'identifiant a été tapé différemment : le nom local dépend du **nom complet** |

Détail technique, protocole du tube et compilation :
[`src/vaultaire_client_windows/README.md`](../../src/vaultaire_client_windows/README.md).
