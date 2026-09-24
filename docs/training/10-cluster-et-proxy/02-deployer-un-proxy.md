[⌂ Formation](../README.md) › [Chapitre 10 — Cluster et proxy](./README.md) › Jalon 10.2

# Jalon 10.2 — Déployer un proxy

[← Clés d'enrôlement](./01-cles-d-enrolement.md) · [Topologie : exposition, affinité, rotation →](./03-topologie.md)

---

## Objectif

Démarrer `vlt-proxy` et le voir apparaître dans le cluster.

## Ce qu'il faut savoir

Le proxy **relaie le Ducky** : les agents d'un site le joignent, il transporte
leurs connexions vers les cores sans les lire. Si aucun core ne répond, il
ferme la connexion tout de suite et l'agent passe au nœud suivant. Il sait aussi
relayer HTTPS vers les Nexus et LDAPS vers les cores ; ce jalon s'en tient au
Ducky. Référence : [`docs/proxy/`](../../proxy/README.md), et
[`https-et-ldaps.md`](../../proxy/https-et-ldaps.md) pour les deux autres.

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

4. Dites aux agents par où joindre le proxy (le port **publié** sur l'hôte) :

   ```bash
   vlt cluster expose <proxy> <IP-de-l-hôte> 6667
   ```

5. Redémarrez un agent, puis regardez le journal du proxy :

   ```bash
   docker compose logs vlt-proxy | grep relais
   ```

## ✅ Vous avez réussi si

`cluster list` montre un nœud de rôle proxy, en ligne, la clé n'a plus d'usage
restant, et le bilan du relais compte au moins une connexion vers un core.

## 🧪 Exercice

Pourquoi `docker compose down -v` sur le proxy impose-t-il une nouvelle clé ?

<details><summary>Solution</summary>

Le volume `vlt_proxy_keys` porte l'**identité** du proxy. Le supprimer fait
repartir de zéro : il doit s'enrôler à nouveau, et la clé à usage unique est
déjà consommée.
</details>

---

[← Clés d'enrôlement](./01-cles-d-enrolement.md) · [Topologie : exposition, affinité, rotation →](./03-topologie.md)
