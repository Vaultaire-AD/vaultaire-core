[⌂ Formation](../README.md) › [Chapitre 11 — Nexus](./README.md) › Jalon 11.2

# Jalon 11.2 — Les dépôts : créer, publier, consommer

[← Déployer et raccorder un Nexus](./01-deployer-et-raccorder.md) · [Changer la version d'un agent par Nexus →](./03-mettre-a-jour-un-agent.md)

---

## Objectif

Créer un dépôt RPM, y publier un paquet avec un **jeton**, l'installer sur
`web01` avec `dnf`, puis vérifier le dépôt du parc `releases`.

## Ce qu'il faut savoir

| Type | Pour | URL de lecture |
|---|---|---|
| `rpm` | `dnf` / `yum` | `/repo/rpm/<dépôt>/` |
| `deb` | `apt` | `/repo/deb/<dépôt>` |
| `docker` | `docker pull` / `push` | `<hôte>:8843/<dépôt>/<image>:<tag>` |
| `vaultaire` | releases Vaultaire, paquets d'agent | `/repo/vaultaire/<dépôt>/` |
| `generic` | fichiers versionnés | `/repo/files/<dépôt>/` |

- Un dépôt **`public`** se lit sans compte ; il ne se **publie jamais** sans
  compte.
- Les dépôts de `config.yaml` sont créés au **premier** démarrage. Ensuite,
  modifier le fichier ne change plus un dépôt existant : on passe par
  l'interface ou l'API.
- Une version publiée est **immuable** : republier le même nom avec un autre
  contenu rend `409`.
- **Jetons** `nxs_…` : pour `dnf`, `apt`, `docker` et la CI. Affichés **une
  fois**, portée `reader` ou `publisher`, et ils n'existent que dans le Nexus
  qui les a créés.

## Étapes

1. Dans l'interface (**Dépôts → Nouveau**), créez `rocky9`, type **RPM**,
   **public**, 5 versions gardées. Ou par l'API, avec le compte `admin` :

   ```bash
   N=https://<IP-serveur>:8843
   curl -sk -u admin -H 'Content-Type: application/json' \
        -d '{"name":"rocky9","type":"rpm","public":true,"keep_versions":5}' $N/api/v1/repos
   ```

2. Créez un jeton de **publication** : **Jetons → Nouveau**, portée
   `publisher`, libellé `ci-lab`. Copiez-le tout de suite.

   ```bash
   read -rs NEXUS_TOKEN && export NEXUS_TOKEN
   ```

3. Récupérez un RPM quelconque et publiez-le :

   ```bash
   dnf download --destdir . tree            # sur web01 (ou toute Rocky), puis copiez-le sur l'hôte
   curl -fsSk -u ci:$NEXUS_TOKEN -T tree-*.x86_64.rpm $N/api/v1/repos/rocky9/upload
   ```

   Le nom, la version et l'architecture sont lus dans l'en-tête RPM. Relancez la
   même commande : `409`, la version existe déjà.

4. Sur `web01`, faites approuver le certificat auto-signé de Nexus, déclarez le
   dépôt et installez :

   ```bash
   N=https://<IP-serveur>:8843
   sudo curl -fsSko /etc/pki/ca-trust/source/anchors/nexus-lab.crt $N/repo/keys/nexus.crt
   sudo update-ca-trust
   sudo curl -fsSLo /etc/yum.repos.d/nexus-rocky9.repo $N/repo/rpm/rocky9/nexus.repo
   sudo dnf remove -y tree
   sudo dnf --disablerepo='*' --enablerepo=nexus-rocky9 install -y tree
   ```

   Le `-k` du premier `curl` est le seul : c'est lui qui va chercher le
   certificat à approuver. Vérifiez-le (`openssl x509 -noout -fingerprint`)
   contre celui de l'hôte avant de lui faire confiance.

5. Regardez le dépôt du parc, celui que les agents liront au jalon suivant :

   ```bash
   curl -sk $N/repo/vaultaire/releases/api/releases | head -20
   ```

   Vide pour l'instant : c'est le core qui y versera les paquets d'agent.

6. Ouvrez **Suivi** dans l'interface : la publication par `ci-lab` et le
   téléchargement par `<IP-web01>` y sont.

## ✅ Vous avez réussi si

`tree` s'installe sur `web01` depuis `nexus-rocky9`, et le suivi montre le
téléchargement.

## 🧪 Exercice

Rendez `rocky9` **privé** et lisible seulement par le groupe `Infra`, puis
refaites l'installation sur `web01`. Que faut-il ajouter au fichier `.repo` ?

<details><summary>Solution</summary>

Page du dépôt → **Réglages** : décochez **public**, ajoutez `Infra` aux
**lecteurs** (ou `PATCH /api/v1/repos/rocky9` avec `{"public":false,"readers":["Infra"]}`).

Sans compte, `dnf` reçoit `401`. Créez un jeton **`reader`** avec un compte du
groupe `Infra`, puis, dans le `.repo` :

```ini
username=lecteur
password=nxs_…
```

Le nom d'utilisateur est libre : seul le jeton compte. **Ne rendez jamais
`releases` privé** : les agents le lisent sans compte, et la mise à jour du
parc échouerait.
</details>

## 📚 Référence

[`vaultaire_nexus/README.md`](../../../src/vaultaire_nexus/README.md) §3
« Dépôts », §4 « Rôles » et « Jetons », §5, §6 (API)

---

[← Déployer et raccorder un Nexus](./01-deployer-et-raccorder.md) · [Changer la version d'un agent par Nexus →](./03-mettre-a-jour-un-agent.md)
