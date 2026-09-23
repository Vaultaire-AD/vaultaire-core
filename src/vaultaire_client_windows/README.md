# Agent Vaultaire pour Windows — V1

Authentifier un utilisateur du domaine Vaultaire sur un poste Windows, par mot
de passe. Rien d'autre, volontairement.

```
   écran de connexion Windows
   LogonUI.exe
     └── VaultaireCredentialProvider.dll        (C++, COM)
            │  tube nommé \\.\pipe\vaultaire_agent   — SYSTEM et administrateurs
            ▼
     vaultaire_client_windows.exe               (Go, service SYSTEM)
            │  tunnel Ducky (le mot de passe voyage dedans)
            ▼
          core  ──► verdict ──► compte Windows local provisionné
```

## Ce que fait la V1

| | |
|---|---|
| ✅ | enrôlement, tunnel Ducky, battement, versions déclarées |
| ✅ | **inventaire système** : nom et build de Windows, mémoire, processeurs, sessions ouvertes — par les API, jamais par `wmic` ou `systeminfo`, dont la sortie est traduite |
| ✅ | **authentification par mot de passe** d'un compte du domaine |
| ✅ | **provisionnement** du compte Windows local correspondant (création, mot de passe aligné, groupes Utilisateurs / Administrateurs) |
| ✅ | **liste des cores et proxies** : découverte `04_04`, ordre servi (affinité, priorité), persistance dans `client_conf.json`, repli sur la configuration |
| ✅ | tuile Vaultaire à l'écran de connexion (Credential Provider) |
| ⏸ | **GPO** : trames reçues et journalisées, **jamais appliquées** |
| ⏸ | **révocations** : même chose — un compte révoqué ne pourra plus s'authentifier, mais sa session en cours n'est pas fermée |
| ❌ | SSH, clés publiques, groupes du domaine : pas de `sshd` ici |
| ❌ | second facteur, changement de mot de passe depuis l'écran de connexion |

## Pourquoi deux composants, et pourquoi un tube nommé

Un Credential Provider est une **DLL chargée dans `LogonUI.exe`**, le processus
qui dessine l'écran de connexion. Ce qui plante là fait disparaître l'écran de
connexion de la machine. Cette DLL doit donc être la plus petite possible : elle
ne parle pas au réseau, ne connaît pas le protocole Ducky, ne détient aucune
clé. Elle pose une question sur un tube et lit la réponse.

Tout le reste vit dans l'agent, un service qui tourne en SYSTEM — c'est lui qui
détient l'identité de la machine, maintient le tunnel et crée les comptes.

Le canal est un **tube nommé** plutôt qu'un port local ou gRPC :

- un tube n'ouvre aucun port : un socket sur la boucle locale est joignable par
  tout utilisateur de la machine, et le mot de passe en clair passe par là ;
- son descripteur de sécurité n'accorde l'accès qu'à **SYSTEM et aux
  administrateurs** (`D:P(A;;GA;;;SY)(A;;GA;;;BA)`) — c'est la décision prise
  pour le socket PAM de l'agent Linux, qui vit en 0700 et refuse tout appelant
  non root ;
- une pile gRPC dans LogonUI, c'est protobuf, des threads et du TLS chargés dans
  le processus le plus critique de la machine, pour transporter quatre champs.

Le format des messages est **celui du canal PAM de l'agent Linux** : une requête
JSON, une réponse JSON. Les deux portes posent la même question au même serveur ;
une seule forme de message évite d'avoir deux vérités sur ce qu'« authentifié »
veut dire.

## Le compte local, et ce que cela implique

Windows n'ouvre de session qu'avec une identité qu'il connaît. Vaultaire n'est
pas un domaine Active Directory, et le devenir demanderait de parler Kerberos et
LDAP comme un contrôleur de domaine. La V1 prend donc le chemin des
fournisseurs d'identité tiers : **le core valide le mot de passe, l'agent crée
un compte local qui le porte**, et Windows ouvre une session ordinaire.

Le nom du compte local est déterministe et distinct :

```
alice@test.fr        →  alice-1f4b2c
alice@autre.fr       →  alice-6b0d19
```

Le suffixe vient de l'empreinte du nom complet. Il tient dans les 20 caractères
de Windows, sépare deux domaines homonymes, et surtout **ne reprend jamais un
compte local existant** — écrire le mot de passe du domaine dans le compte
`alice` d'un poste serait une prise de contrôle, pas un provisionnement.

Conséquences assumées en V1 :

- le mot de passe local est **réaligné à chaque connexion réussie** : changer son
  mot de passe dans le portail suffit, la connexion suivante suit ;
- un compte dont l'utilisateur ne se connecte plus **garde son dernier mot de
  passe**. Une révocation côté core empêche la prochaine authentification, pas
  l'usage d'un mot de passe déjà connu.

## Compiler

```bash
./build.sh                    # dist/vaultaire-client-windows-<version>.tar
./build.sh --version 2.2.1
./build.sh --sans-dll         # sans le Credential Provider
```

Depuis Linux, sans Windows : `GOOS=windows go build` suffit (aucun CGO), et la
DLL se compile avec MinGW (`apt install mingw-w64`).

### Compiler la DLL avec MSVC

Si vous préférez la chaîne Microsoft (Visual Studio, SDK Windows) :

```
cl /LD /EHsc /DUNICODE /D_UNICODE /std:c++17 ^
   credential_provider\vaultaire_*.cpp ^
   /Fe:VaultaireCredentialProvider.dll ^
   /link /DEF:credential_provider\vaultaire_cp.def ^
   ole32.lib oleaut32.lib uuid.lib secur32.lib advapi32.lib
```

Le résultat est interchangeable : les points d'entrée COM sont les mêmes, et
c'est le fichier `.def` qui garantit leurs noms non décorés.

## Installer sur un poste

L'archive s'installe **à la main**, sans MSI et sans rien faire tout seul.

```powershell
# 1. Sur le CORE : créer l'identité de la machine
vlt create -c poste-win01
#    → <config>/clientsoftware/<id>/  (client_software.yaml + private_key.pem)
#    Copiez ce dossier sur le poste.

# 2. Sur le POSTE, invite PowerShell ADMINISTRATEUR, archive décompressée :
.\install.ps1
```

`install.ps1` demande : le dossier d'identité, les cores joignables, l'empreinte
du core (facultative mais recommandée), s'il faut installer le service, et s'il
faut enregistrer la tuile de l'écran de connexion. Il pose aussi les droits sur
`C:\ProgramData\Vaultaire` — SYSTEM et administrateurs seulement, la clé privée
de la machine est là.

> **Un agent ne s'enrôle pas seul.** Seuls les SERVICES du cluster (proxy,
> Nexus) le font avec une clé d'enrôlement ; l'identité d'une machine est créée
> sur le core. C'est pourquoi l'installeur réclame un dossier d'identité.

## Éprouver sans toucher à l'écran de connexion

```powershell
vaultaire_login.exe -etat                    # l'agent est-il raccordé à un core ?
vaultaire_login.exe -u alice@test.fr         # authentification complète
vaultaire_login.exe -u alice@test.fr -check  # vérifier SANS créer de compte local
```

`vaultaire_login` fait exactement ce que fait la DLL : même tube, mêmes
messages. Déverminer un Credential Provider se fait dans `LogonUI.exe`, qu'on ne
peut ni attacher facilement ni voir planter sans perdre l'écran de connexion —
donc **tout ce qui peut être éprouvé avant doit l'être ici**.

> ⚠️ En enregistrant la tuile pour la première fois, gardez une session
> administrateur **ouverte**. Si quelque chose cloche,
> `.\uninstall.ps1 -CredentialProviderSeulement` rend l'écran de connexion
> d'origine sans toucher au reste.

## Où vivent les choses

| Chemin | Contenu |
|---|---|
| `C:\ProgramData\Vaultaire\client_conf.json` | cores déclarés (`servers`) et appris (`learned`) |
| `C:\ProgramData\Vaultaire\client_software.yaml` | identité de la machine, créée par le core |
| `C:\ProgramData\Vaultaire\keys\` | clé privée, clé du core, empreintes de confiance |
| `C:\ProgramData\Vaultaire\logs\vaultaire_client_windows.log` | journal de l'agent |
| `C:\ProgramData\Vaultaire\logs\credential_provider.log` | journal de la DLL (écran de connexion) |
| `C:\ProgramData\Vaultaire\bin\` | binaires installés |

## Diagnostic

| Symptôme | Cause probable |
|---|---|
| La tuile n'apparaît pas | DLL non enregistrée (`regsvr32`), ou dépendance manquante — elle doit être liée en statique |
| « Service Vaultaire arrêté sur ce poste » | `sc query VaultaireAgent` ; le tube n'existe que si l'agent tourne |
| « Aucun serveur Vaultaire joignable » | pare-feu, ou `servers` faux dans `client_conf.json` |
| Refus alors que le mot de passe est bon | le compte a-t-il le droit sur cette machine ? le motif exact est dans le journal du **core** |
| Mot de passe accepté, session refusée par Windows | compte local non inscrit dans Utilisateurs, ou stratégie « Interdire l'ouverture de session locale » |
| Le compte local existe mais le profil est vide | deux comptes ont été créés : vérifiez que l'identifiant est tapé de la même façon (le nom local est déterministe, voir plus haut) |

Les deux journaux se lisent ensemble : la DLL dit ce qu'elle a demandé, l'agent
dit ce que le core a répondu.
