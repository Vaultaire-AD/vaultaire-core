package client

import (
	"database/sql"
	"fmt"
	"strconv"

	dbusers "vaultaire/core/database/db_users"
	logs "vaultaire/core/logs"
	"vaultaire/core/storage"
	"vaultaire/ducky-network/ducky_tools"
	"vaultaire/ducky-network/sendmessage"
)

// RefusClesTropLourdes est ce que le poste reçoit, dans la 02_07, quand la
// trame d'acceptation d'un compte ne peut pas être émise (TO-DO 138).
//
// Le poste l'écrit dans son journal à côté du nom du compte : c'est la seule
// trace que l'utilisateur, ou qui le dépanne, trouvera de son côté.
const RefusClesTropLourdes = "trop de cles SSH sur ce compte pour qu'elles soient transmises au poste : " +
	"un administrateur doit en retirer"

// margeEnveloppe couvre ce que la 02_04 porte en plus des clés et du nom, pour
// l'estimation faite au démarrage : l'en-tête, la clé d'intégrité de la
// session — qu'on ne connaît pas hors d'une session — et le texte final.
// Large à dessein : une estimation qui annonce « elle part » à tort est la
// seule erreur qui coûte.
const margeEnveloppe = 512

// Acceptation compose la trame 02_04 : le compte est authentifié, voici ses
// clés publiques.
//
// Une fonction, et non deux concaténations dans CheckAuth : la taille de cette
// trame décide si le compte peut ouvrir une session, et ce qui la mesure doit
// mesurer exactement ce qui part.
func Acceptation(cleIntegrite, utilisateur string, administrateur bool, cles string) string {
	return "02_04\nserveur_central\n" + cleIntegrite + "\n" + utilisateur + "\n" +
		strconv.FormatBool(administrateur) + "\n" + cles + "\nYou are authentificate Has : \n" + utilisateur
}

// ComposerAcceptation rend la 02_04 d'un compte authentifié, et dit si elle
// TIENT dans une trame.
//
// Séparée de CheckAuth, qui a besoin d'une base et d'une session : c'est ici
// que se décide « accepté » ou « refusé pour le poids de ses clés », et cette
// décision doit pouvoir être éprouvée seule.
//
// Une lecture des clés en échec ne refuse pas la connexion : le compte entre
// sans clé publique — « empty » —, comme avant.
func ComposerAcceptation(cleIntegrite, utilisateur string, administrateur bool,
	cles []storage.PublicKey, erreurDeLecture error) (trame string, tient bool) {

	publiques := "empty"
	if erreurDeLecture == nil {
		publiques = ducky_tools.ExtractPublicKeys(cles)
	}
	trame = Acceptation(cleIntegrite, utilisateur, administrateur, publiques)
	return trame, sendmessage.TientDansUneTrame(trame)
}

// RefusPourPoids compose la 02_07 rendue à un compte dont l'acceptation ne
// tient pas dans une trame. Deux lignes de contenu, le compte puis le motif :
// c'est ce que le poste écrit dans son journal.
func RefusPourPoids(cleIntegrite, utilisateur string) string {
	return "02_07\nserveur_central\n" + cleIntegrite + "\n" + utilisateur + "\n" + RefusClesTropLourdes
}

// MessageClesTropLourdes est la ligne du journal du core quand l'acceptation
// d'un compte ne tient pas dans une trame.
//
// Elle NOMME le compte et dit quoi faire : avant ce point, la seule trace
// était « trame de N octets : dépasse la taille maximale », sans rien qui
// permette de savoir de qui il s'agissait.
func MessageClesTropLourdes(utilisateur string, cles, octets int) string {
	return fmt.Sprintf(
		"clés SSH : le compte %q ne peut plus ouvrir de session Ducky — ses %d clé(s) font une trame 02_04 de %d octets, "+
			"%d une fois chiffrée, pour un maximum de %d. Connexion REFUSÉE, aucune clé retirée. "+
			"Retirez-en : « vlt get -u %s -k » liste les clés, « vlt remove -u %s -k <id_clé> » en retire une",
		utilisateur, cles, octets, sendmessage.TailleChiffree(octets), sendmessage.TailleMaxCorps,
		utilisateur, utilisateur)
}

// SignalerLesComptesHorsBornes écrit, au démarrage du core, une ligne par
// compte dont les clés SSH dépassent les bornes de l'ajout (TO-DO 138). Rend
// le nombre de comptes signalés.
//
// # Deux gravités, parce que ce sont deux situations
//
// Dépasser une borne n'empêche rien tant que la trame part : c'est un WARNING,
// et le compte fonctionne. Quand l'estimation dit qu'elle ne partira pas, le
// compte est DÉJÀ refusé à chaque connexion : c'est une ERROR, et elle le dit.
//
// # Rien n'est retiré
//
// Ni ici ni ailleurs. Ce relevé nomme ; c'est à un administrateur de choisir
// quelles clés partent.
func SignalerLesComptesHorsBornes(db *sql.DB) int {
	comptes, err := dbusers.ComptesHorsBornes(db)
	if err != nil {
		logs.Write_Log("ERROR", "bootstrap: "+err.Error())
		return 0
	}
	for _, c := range comptes {
		logs.Write_Log(GraviteDuDepassement(c), MessageDuDepassement(c))
	}
	return len(comptes)
}

// tailleEstimee rend la taille de la 02_04 du compte, hors chiffrement : ses
// clés, les virgules qui les joignent, son nom deux fois, et l'enveloppe.
func tailleEstimee(c dbusers.CompteHorsBornes) int {
	virgules := 0
	if c.Cles > 1 {
		virgules = c.Cles - 1
	}
	return c.Caracteres + virgules + 2*len(c.Utilisateur) + margeEnveloppe
}

// GraviteDuDepassement rend ERROR si la trame du compte ne partira pas,
// WARNING si elle part encore.
func GraviteDuDepassement(c dbusers.CompteHorsBornes) string {
	if sendmessage.TailleChiffree(tailleEstimee(c)) > sendmessage.TailleMaxCorps {
		return "ERROR"
	}
	return "WARNING"
}

// MessageDuDepassement compose la ligne du relevé de démarrage.
func MessageDuDepassement(c dbusers.CompteHorsBornes) string {
	taille := sendmessage.TailleChiffree(tailleEstimee(c))
	consequence := fmt.Sprintf(
		"Sa trame d'authentification fait environ %d octets sur %d : elle part encore, mais plus rien ne le garantit",
		taille, sendmessage.TailleMaxCorps)
	if taille > sendmessage.TailleMaxCorps {
		consequence = fmt.Sprintf(
			"Sa trame d'authentification ferait environ %d octets pour un maximum de %d : "+
				"ce compte NE PEUT PLUS ouvrir de session Ducky, sur aucun poste",
			taille, sendmessage.TailleMaxCorps)
	}
	return fmt.Sprintf(
		"clés SSH : le compte %q porte %s — au-delà de ce que l'ajout accepte depuis la 2.2. %s. "+
			"Aucune clé n'est retirée : « vlt get -u %s -k » les liste, « vlt remove -u %s -k <id_clé> » en retire une",
		c.Utilisateur, c.Motif(), consequence, c.Utilisateur, c.Utilisateur)
}
