[⌂ Ducky Network](../README.md) › [Chapitre 1 — Le socle : canal, format, contrôles](./README.md) › 1.2

# 1.2 — Format des trames

[← Chiffrement du canal](./01-chiffrement.md) · [Types de client, ordre et contrôles →](./03-types-ordre-et-controles.md)

---


```go
lines := strings.Split(trames, "\n")
action              = lines[0]          // "XX_YY"
Destination_Server  = lines[1]
SessionIntegritykey = lines[2]
Username            = lines[3]          // peut contenir un domaine (ex: admin@vaultaire.fr)
ClientSoftwareID    = lines[4]
Content             = lines[5:]         // tout le reste, rejoint par \n

//Structure exacte à respecter, ligne par ligne :
XX_YY
<destination>
<session_integrity_key>
<username>
<client_software_id>
<contenu ligne 1>
<contenu ligne 2>
...

//EXEMPLE
msg := "03_01\nserveur_central\n" + SessionKey + "\nvaultaire\n" + Computeur_ID + "\n" + req.User + "\n" + req.Password
```

## Format Serveur → Client

```go
lines := strings.Split(trames, "\n")
action              = lines[0]          // "XX_YY"
Destination_Server  = lines[1]
SessionIntegritykey = lines[2]
Content             = lines[3:]         // tout le reste, rejoint par \n

//Structure exacte à respecter :
XX_YY
<destination>
<session_integrity_key>
<contenu ligne 1>
<contenu ligne 2>
...
//EXEMPLE
return "03_02\nserveur_central\n" + SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\n" + isAdmin + "\n" + clesPubliques
```

---

[← Chiffrement du canal](./01-chiffrement.md) · [Types de client, ordre et contrôles →](./03-types-ordre-et-controles.md)
