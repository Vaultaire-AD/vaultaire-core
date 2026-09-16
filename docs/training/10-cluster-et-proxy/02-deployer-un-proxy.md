[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.2

# Jalon 10.2 — Déployer un proxy

[← Clés d'enrôlement](./01-cles-d-enrolement.md) · [Topologie : exposition, affinité, rotation →](./03-topologie.md)

---

## Objectif

Démarrer `vlt-proxy` et le voir apparaître dans le cluster.

## Ce qu'il faut savoir

Aujourd'hui le proxy est **visible du cluster et connaît ses cores**, mais il
**ne relaie pas encore** le trafic (TO-DO 38). Ce jalon valide l'enrôlement et
la topologie.

## Étapes

1. Dans `deployments/pre-prod/vlt-proxy/docker-compose.yml`, renseignez :

   ```yaml
         - VAULTAIRE_IP_CORE=vaultaire-ad:6666
         - VAULTAIRE_ENROLL_KEY=VLT-ENR-…        # la clé du jalon 1
         - VAULTAIRE_ENROLL_LABEL=proxy-lab
   ```

2. Démarrez-le :

   ```bash
   cd deployments/pre-prod/vlt-proxy
   docker compose up -d
   docker compose logs -f vlt-proxy
   ```

3. Côté core :

   ```bash
   vlt cluster list
   vlt get -c
   vlt enroll show <id>
   ```

## ✅ Vous avez réussi si

`cluster list` montre un nœud de rôle proxy, en ligne, et la clé n'a plus
d'usage restant.

## 🧪 Exercice

Pourquoi `docker compose down -v` sur le proxy impose-t-il une nouvelle clé ?

<details><summary>Solution</summary>

Le volume `vlt_proxy_keys` porte l'**identité** du proxy. Le supprimer fait
repartir de zéro : il doit s'enrôler à nouveau, et la clé à usage unique est
déjà consommée.
</details>

---

[← Clés d'enrôlement](./01-cles-d-enrolement.md) · [Topologie : exposition, affinité, rotation →](./03-topologie.md)
