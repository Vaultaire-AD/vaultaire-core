[⌂ Formation](../README.md) › [Chapitre 1 — Installer le serveur](./README.md) › Jalon 1.2

# Jalon 1.2 — Démarrer la pile

[← Préparer l'hôte](./01-preparer-l-hote.md) · [Premier accès et sécurisation →](./03-premier-acces.md)

---

## Objectif

Lancer Vaultaire et comprendre ce que fait le premier démarrage.

## Étapes

1. Installez la dernière release et démarrez :

   ```bash
   ./deployments/pre-prod/docker-update.sh
   ```

   Le script télécharge les archives, vérifie leurs sommes SHA-256, place le
   dépôt sur le tag de la release, installe les binaires dans `cmd/` et
   construit l'image au premier passage.

2. Vérifiez les conteneurs :

   ```bash
   docker compose -f deployments/pre-prod/docker-compose.yml ps
   ```

3. Suivez le journal du core :

   ```bash
   docker compose -f deployments/pre-prod/docker-compose.yml logs -f vaultaire-ad
   ```

## Ce que fait le premier démarrage

Sans aucune intervention, le core :

1. crée les tables de la base ;
2. crée l'**identité d'amorçage** : l'utilisateur `vaultaire`, le groupe
   `vaultaire` (domaine `vaultaire.fr`) et la permission `vaultaire_all` ;
3. crée le compte `admin` décrit dans la section `administreur` de
   `deployments/configs/serveur_conf.yaml` ;
4. génère **sa paire de clés** et les certificats TLS (portail, API, LDAPS),
   stockés en base ;
5. journalise l'**empreinte** de sa clé — la ligne qui prouve que tout est prêt :

   ```
   keymanagement: empreinte du core SHA256:…
   ```

## ✅ Vous avez réussi si

- les trois conteneurs sont `running` ;
- la ligne `empreinte du core` apparaît dans le journal.

## 🧪 Exercice

Retrouvez **quelle version** du core tourne, de deux façons différentes.

<details><summary>Solution</summary>

```bash
cat cmd/.release                                   # la release installée par le script
docker exec vaultaire-ad /opt/vaultaire/bin/vaultaire_cli version
```

La seconde affiche `2.1.x+g<commit> (date)` : la version, le commit compilé et
la date du build.
</details>

## En cas de problème

| Symptôme | Piste |
|---|---|
| `vaultaire-ad` redémarre en boucle, « binaire serveur absent » | la release n'est pas installée : relancez `docker-update.sh --force` |
| `Impossible d'amorcer les clés du core` | la base n'est pas prête ou pas joignable : `logs vaultaire-db` |
| port déjà utilisé | un service de l'hôte occupe le port : arrêtez-le ou modifiez `ports` dans le compose |

---

[← Préparer l'hôte](./01-preparer-l-hote.md) · [Premier accès et sécurisation →](./03-premier-acces.md)
