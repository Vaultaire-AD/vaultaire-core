[⌂ Ducky Network](../README.md) › [Chapitre 1 — Le socle : canal, format, contrôles](./README.md) › 1.2

# 1.2 — Format des trames

[← Chiffrement du canal](./01-chiffrement.md) · [Types de client, ordre et contrôles →](./03-types-ordre-et-controles.md)

---

## Cadrage sur le socket

Avant tout découpage en lignes, une trame voyage ainsi :

```
[1 octet : 0x02][2 octets : taille du corps, big-endian][corps, chiffré]
```

| Règle | Pourquoi |
| --- | --- |
| Le premier octet vaut **toujours 2** — toute autre valeur ferme la connexion, `0` compris | Il annonce la longueur du champ taille, qui fait deux octets chez tous les émetteurs. Lu comme une longueur libre, `\x01\xff` faisait paniquer le core sans authentification (TO-DO 101) |
| Le corps fait de **1 à 65 535 octets** | Un corps vide n'a pas d'émetteur ; au-delà de 65 535, deux octets ne savent pas l'annoncer |
| À l'émission, une trame trop grande est **refusée**, pas tronquée | `uint16(len)` l'annonçait modulo 65 536 : le pair prenait la fin pour un nouvel en-tête et le tunnel restait désynchronisé |
| Toute lecture passe par `io.ReadFull` | TCP peut livrer une trame octet par octet, sans attaquant. `conn.Read` prenait un morceau pour le tout |
| Une erreur de cadrage **ferme la connexion** ; un échec de déchiffrement, non | Après la première, on ne sait plus où commence la trame suivante. Après le second, le corps a été lu jusqu'au bout : le flux est intact |

Le code vit dans **deux jumeaux** qui doivent rester identiques :
`vaultaire_serveur/ducky-network/trames_manager/cadrage.go` (core) et
`ducky-network-sdk-service/duckynetwork/trames_manager/cadrage.go` (SDK : agent,
proxy, Nexus, client Windows). L'assemblage à l'émission est
`sendmessage.CadrerTrame`, des deux côtés. Un test-sentinelle de chaque côté
interdit tout `conn.Read` réintroduit.

**Conséquence sur le contenu.** La trame `02_04` porte toutes les clés SSH du
compte : c'est ce qui borne un compte à 10 clés de 4 096 caractères
(`dbusers.MaxClesParCompte`, `dbusers.LongueurMaxCle`). Le pire cas, chiffré,
fait environ 56 000 octets ; un test échoue si l'une des bornes est relevée sans
refaire le calcul.

Une fois déchiffré, le corps se découpe en lignes. Le minimum est de **cinq**
lignes dans le sens client → serveur et de **trois** dans l'autre ; en dessous,
la trame est ignorée des deux côtés (le SDK ne le vérifiait pas avant le TO-DO 101).

## Format Client → Serveur

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
