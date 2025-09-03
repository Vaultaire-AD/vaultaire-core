# vaultaire_ctl

vaultaire_ctl est le binaire qui va vous servir a communiqué avec vos serveur vaultaire via l'api 

## setup up

téléchargé le binaire [ici](/cmd/vaultaire_server/vaultaire_clt)
```sh
mv /mnt/vaultaire_cli/vaultaire_ctl /usr/local/bin/vlt
chown user:group /usr/local/bin/vlt
chmod 750 /usr/local/bin/vl
```

puis dans le repertoire de votre utilisateur crée un fichier config avec :
l'adresse du serveur le nom de votre utilisateur et le path vers votre clé public 
que vous devrait ajouter via la portail web du service vaultaire si c'est activé ou 
en demandant a votre administrateur d'ajouter votre clé public
```sh
cat ~/.vaultaire/config.json 
{
  "server": "https://192.168.10.57:6643",
  "username": "alice",
  "private_key": "/root/.ssh/id_rsa"
}
```


## utilisation

une fois la phase de setup terminée c'est tous good
et vous pouvez utilise les commandes comme avec vaultaire_cli  qui lui sert a administré vaultaire sur les host directement

```sh
[root@Vaultaire-Serveur ~]# vlt get -u
✅ Résultat: 👥 Liste de tous les Utilisateurs
--------------------------------------------------
ID Utilisateur  Username                  Date de Naissance Créé à              
1               vaultaire                 1990-01-01      2025-07-13 14:09:44 
2               alice                     1992-02-06      2025-07-13 14:12:20 
3               bob                       1988-12-09      2025-07-13 14:12:20 
4               fiona                     1985-07-08      2025-07-13 14:12:20 
5               julie                     1994-09-10      2025-07-13 14:12:20 
6               charlie                   1995-09-03      2025-07-13 14:12:20 
7               diana                     1990-07-01      2025-07-13 14:12:20 
8               eric                      1993-01-30      2025-07-13 14:12:20 
9               george                    1997-11-12      2025-07-13 14:12:20 
10              hannah                    1991-02-04      2025-07-13 14:12:20 
11              isaac                     1989-03-05      2025-07-13 14:12:20 
12              proxmox_ldap_account      2004-01-06      2025-07-13 14:12:20 
29              bryan.feur                1992-02-06      2025-08-02 11:50:04 
--------------------------------------------------
```

## coté logs

chaque request api est enregistré dans les logs
```sh
tail -n 1 /var/log/vaultaire/vaultaire.log | 
2025-09-03 23:22:26 [INFO] 🕵️ User: alice | Command: get -u | Status: SUCCESS
```