package gpomanager

import (
	"database/sql"
	"strconv"

	database "vaultaire/core/database"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	keymanagement "vaultaire/ducky-network/key_management"
)

// Signature des politiques, côté core (TO-DO 52).
//
// # Où la signature voyage
//
// En QUEUE du manifeste (05_02 / 05_06), sur une ligne préfixée — la recette
// déjà éprouvée par `refresh:` et `sync:`. Les six champs du manifeste gardent
// leur rang, un agent d'une version antérieure les lit et ignore le reste, et
// un core d'une version antérieure n'envoie rien.
//
// Le champ `signature` existe pourtant DANS le document de politique, et il
// n'est pas utilisé : y mettre la valeur aurait changé les octets signés après
// coup — on signe un document, on y insère la signature, et le document n'est
// plus celui qui a été signé. Il aurait fallu une forme canonique, donc une
// seconde implémentation du hachage côté agent, ce que ce paquet refuse par
// ailleurs pour l'empreinte de politique. La ligne de manifeste évite tout cela.

// PrefixeSignature ouvre la ligne de signature du manifeste.
//
// Déclaré des deux côtés du réseau et figé par des tests jumeaux : rien ne lie
// ces deux chaînes à la compilation.
const PrefixeSignature = "sig:"

// PrefixeSignatureExigee ouvre la ligne qui dit si l'agent doit REFUSER une
// politique non signée.
//
// # Pourquoi l'exigence est poussée, et pas décidée par l'agent
//
// La règle « l'agent qui détient la clé exige une signature » aurait été plus
// simple, et irréversible : revenir en arrière aurait demandé de repasser sur
// chaque machine pour retirer un fichier. Une migration dont on ne peut pas
// sortir n'est pas une migration, c'est un pari.
//
// Poussée depuis le core, l'exigence s'active pour tout le parc en une
// commande, et se retire de la même façon — comme la cadence de
// rafraîchissement, et pour la même raison.
const PrefixeSignatureExigee = "sigreq:"

// CleSignatureExigee est le réglage correspondant, dans `server_settings`.
//
// Un entier et non un booléen : `dbsettings` ne connaît que des entiers bornés,
// et ajouter un type pour une valeur à deux états aurait coûté plus que les
// deux lignes de conversion.
const CleSignatureExigee = "gpo_signature_required"

// Par défaut, l'exigence est DÉSACTIVÉE.
//
// C'est le seul défaut tenable : à la mise à jour d'un core, le parc n'a pas
// encore la clé de signature. Un défaut à « exiger » aurait coupé toutes les
// politiques du parc au redémarrage du core — c'est-à-dire transformé un
// durcissement en panne générale, au moment précis où personne ne cherche la
// cause de ce côté.
const (
	SignatureExigeeDefaut = 0
	signatureExigeeMin    = 0
	signatureExigeeMax    = 1
)

// SignatureExigee dit si le core demande aux agents de refuser une politique
// non signée.
func SignatureExigee(db *sql.DB) bool {
	return dbsettings.GetInt(db, CleSignatureExigee,
		signatureExigeeMin, signatureExigeeMax, SignatureExigeeDefaut) == 1
}

// DefinirSignatureExigee écrit le réglage.
func DefinirSignatureExigee(db *sql.DB, exigee bool, parQui string) error {
	valeur := 0
	if exigee {
		valeur = 1
	}
	return dbsettings.SetInt(db, CleSignatureExigee, valeur,
		signatureExigeeMin, signatureExigeeMax, parQui)
}

// lignesSignature compose les lignes à ajouter en queue d'un manifeste.
//
// # Une signature qui manque n'empêche PAS la livraison
//
// La clé peut être absente d'une base plus ancienne, ou illisible. Refuser de
// livrer la politique ferait, d'un défaut de la clé de signature, une panne
// d'application des GPO sur tout le parc — pour un mécanisme dont l'objet est
// de rendre ces GPO plus sûres. La trame part sans sa ligne, l'agent l'applique
// comme avant, et le journal dit pourquoi.
//
// La ligne d'EXIGENCE, elle, part dans tous les cas : c'est elle qui permet à
// l'administrateur de constater que le parc est prêt avant de l'activer.
func lignesSignature(clientID string, m gpo.Manifest) []string {
	var out []string

	signature, err := keymanagement.SignerLivraison(
		clientID, string(m.Scope), m.Username, m.Fingerprint, m.Checksum)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeGPOTransport,
			"gpo: politique non signée pour "+clientID+" : "+err.Error())
	} else {
		out = append(out, PrefixeSignature+signature)
	}

	exigee := 0
	if SignatureExigee(database.GetDatabase()) {
		exigee = 1
	}
	return append(out, PrefixeSignatureExigee+strconv.Itoa(exigee))
}
