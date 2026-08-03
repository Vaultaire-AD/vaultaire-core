package keydecodeencode

import (
	"crypto/sha256"
	"hash"
)

// Paramètres du chiffrement asymétrique du canal Ducky.
//
// POURQUOI OAEP ET PLUS PKCS#1 v1.5.
//
// Le bourrage v1.5 est vulnérable à l'attaque de Bleichenbacher : un oracle de
// bourrage à texte chiffré choisi. Sur Vaultaire, les trois conditions étaient
// réunies, et c'est ce qui rendait le défaut exploitable à distance sans
// posséder le moindre identifiant :
//
//   - la clé publique du serveur s'obtient par un « askkey » NON authentifié ;
//   - tant que IsSafe est faux, le serveur déchiffre avec sa clé privée TOUT ce
//     qu'on lui envoie (voir trames_manager/ReadMessageContent.go) ;
//   - l'échec de déchiffrement était distinguable — journal CRITICAL, et
//     comportement différent en aval.
//
// Un attaquant ayant enregistré un échange de clé de session pouvait donc la
// déchiffrer hors ligne, en quelques millions de requêtes. OAEP ferme ce chemin :
// son bourrage est probabiliste et sa vérification ne fuit pas d'information
// exploitable sur le texte clair.
//
// LES DEUX CÔTÉS DOIVENT ÊTRE STRICTEMENT IDENTIQUES. Un SHA-256 d'un côté et un
// SHA-1 de l'autre, ou un label non nul quelque part, produit un échec de
// déchiffrement qui ressemble en tout point à une mauvaise clé — donc des heures
// perdues à chercher au mauvais endroit. Le pendant de ce fichier est
// src/vaultaire_client/duckynetworkClient/key_encode_decode/oaep_params.go, et
// les deux doivent être modifiés ensemble ou pas du tout.
//
// SHA-256 et pas SHA-1 : rien n'impose ici la compatibilité avec un écosystème
// tiers, contrairement au TOTP où les applications d'authentification imposent
// SHA-1. Les deux extrémités sont écrites par le projet, autant prendre le hachage
// le plus solide.

// oaepHash est la fonction de hachage du bourrage OAEP.
//
// Retournée par un constructeur et non stockée en variable : hash.Hash porte un
// état interne, une instance partagée entre deux chiffrements concurrents
// produirait des résultats faux.
func oaepHash() hash.Hash { return sha256.New() }

// oaepLabel est le label OAEP, volontairement nil.
//
// Le label lie un texte chiffré à un contexte : il doit être identique au
// chiffrement et au déchiffrement, et sert à empêcher qu'un chiffré destiné à un
// usage soit rejoué dans un autre. Vaultaire n'a qu'un seul usage du chiffrement
// asymétrique — la poignée de main Ducky — donc il n'apporterait rien
// aujourd'hui.
//
// Si un second usage apparaît (l'enrôlement des programmes proxy/webserver
// discuté dans Architecture_Multi_Programmes.md, par exemple), c'est ici qu'il
// faudra distinguer les contextes plutôt que de réutiliser le même chiffrement
// partout.
var oaepLabel []byte = nil

// MaxOAEPPayload retourne la taille maximale chiffrable pour une clé donnée.
//
// OAEP consomme 2*hLen + 2 octets de bourrage, contre 11 pour PKCS#1 v1.5. Sur
// les clés RSA-4096 du canal Ducky, la charge utile passe donc de 501 à 446
// octets.
//
// Vérifié au moment de la migration : la plus grosse trame antérieure à IsSafe
// est le 02_01, soit environ 112 octets d'en-tête (action, destination, UUID de
// session, nom d'utilisateur, identifiant machine) plus le mot de passe. Il reste
// donc plus de 330 caractères de marge, et aucune fragmentation n'est nécessaire.
//
// Exposée pour que ce calcul soit vérifiable au lieu d'être une note de
// commentaire qui vieillira.
func MaxOAEPPayload(keySizeBytes int) int {
	overhead := 2*sha256.Size + 2
	if keySizeBytes <= overhead {
		return 0
	}
	return keySizeBytes - overhead
}
