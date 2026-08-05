package keyencodedecode

import (
	"crypto/sha256"
	"hash"
)

// Paramètres du chiffrement asymétrique du canal Ducky.
//
// # OAEP, et surtout PAS PKCS#1 v1.5
//
// Le bourrage v1.5 est vulnérable à l'attaque de Bleichenbacher. Sur Vaultaire
// les trois conditions étaient réunies : clé publique du serveur obtenable par un
// « askkey » non authentifié, déchiffrement de tout ce qui arrive tant que
// IsSafe est faux, et échec distinguable. Le core a migré vers OAEP.
//
// LES DEUX CÔTÉS DOIVENT ÊTRE STRICTEMENT IDENTIQUES. Un hachage différent ou un
// label non nul produit un échec de déchiffrement qui ressemble en tout point à
// une mauvaise clé — donc des heures perdues à chercher au mauvais endroit. Le
// pendant est key_decode_encode/oaep_params.go côté serveur, et les deux se
// modifient ensemble ou pas du tout.
func oaepHash() hash.Hash { return sha256.New() }

// oaepLabel est volontairement nil, comme côté serveur.
var oaepLabel []byte = nil

// MaxOAEPPayload retourne la taille maximale chiffrable pour une clé donnée.
//
// OAEP consomme 2*hLen + 2 octets contre 11 pour v1.5 : sur RSA-4096 la charge
// utile passe de 501 à 446 octets. Exposée pour que le calcul soit vérifiable
// plutôt que d'être une note de commentaire qui vieillira.
func MaxOAEPPayload(keySizeBytes int) int {
	overhead := 2*sha256.Size + 2
	if keySizeBytes <= overhead {
		return 0
	}
	return keySizeBytes - overhead
}
