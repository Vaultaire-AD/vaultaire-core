package keyencodedecode

import (
	"crypto/sha256"
	"hash"
)

// Paramètres du chiffrement asymétrique du canal Ducky, côté agent.
//
// CE FICHIER EST LE MIROIR EXACT de
// src/vaultaire_serveur/ducky-network/key_decode_encode/oaep_params.go.
//
// Les deux modules Go sont séparés — l'agent ne peut pas importer le serveur —
// donc ces constantes sont nécessairement dupliquées. C'est la seule duplication
// assumée du projet, et elle a une contrepartie stricte : toute modification ici
// doit être faite de l'autre côté dans le même commit. Une divergence produit un
// échec de déchiffrement qui ressemble en tout point à une mauvaise clé, ce qui
// envoie chercher au mauvais endroit.
//
// POURQUOI OAEP ET PLUS PKCS#1 v1.5. Le bourrage v1.5 est vulnérable à l'attaque
// de Bleichenbacher : le serveur déchiffrait avec sa clé privée toute trame reçue
// avant l'établissement de la clé de session, sa clé publique s'obtenait sans
// authentification, et l'échec était observable. Cela donnait un oracle de
// déchiffrement à un pair non authentifié. OAEP ferme ce chemin.

// OAEPHash est la fonction de hachage du bourrage OAEP. Doit valoir SHA-256 des
// deux côtés du canal.
//
// Retournée par un constructeur et non stockée en variable : hash.Hash porte un
// état interne, une instance partagée entre deux chiffrements concurrents
// produirait des résultats faux.
//
// EXPORTÉE parce que le paquet serveurauth chiffre lui aussi vers le serveur
// (le défi d'authentification) et doit employer exactement les mêmes paramètres.
// Lui laisser recopier sha256.New() aurait créé un troisième endroit à maintenir
// en cohérence, dont deux dans le même module — c'est-à-dire un endroit de trop
// même en étant indulgent.
func OAEPHash() hash.Hash { return sha256.New() }

// OAEPLabel est le label OAEP, nil des deux côtés.
//
// Le label lie un texte chiffré à un contexte, et doit être identique au
// chiffrement et au déchiffrement. Vaultaire n'a qu'un usage du chiffrement
// asymétrique — la poignée de main Ducky — donc il n'apporterait rien
// aujourd'hui. C'est ici qu'il faudra distinguer les contextes si un second
// usage apparaît.
var OAEPLabel []byte = nil

// MaxOAEPPayload retourne la taille maximale chiffrable pour une clé donnée.
//
// OAEP consomme 2*hLen + 2 octets, contre 11 pour PKCS#1 v1.5 : sur les clés
// RSA-4096 du canal Ducky, la charge utile passe de 501 à 446 octets. Les trames
// antérieures à l'établissement de la clé de session tiennent largement dans
// cette borne — la plus grosse, le 02_01, fait environ 112 octets d'en-tête plus
// le mot de passe.
func MaxOAEPPayload(keySizeBytes int) int {
	overhead := 2*sha256.Size + 2
	if keySizeBytes <= overhead {
		return 0
	}
	return keySizeBytes - overhead
}
