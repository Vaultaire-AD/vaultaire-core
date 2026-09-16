package ducky_tools

import "strings"

// Lecture des versions dans l'inventaire 02_12.
//
// # La disposition de la trame
//
//	[0] hostname
//	[1] os
//	[2] ram
//	[3] processeur
//	[4] sessions actives (séparées par des virgules)
//	[5] version du programme        ← ajouté
//	[6] version du socle réseau     ← ajouté
//
// Les deux dernières sont en QUEUE, et facultatives. Un agent resté à
// l'ancienne version envoie cinq lignes : il est enregistré sans version, et
// apparaît « inconnue » dans les vues. C'est exactement l'information utile
// devant un déploiement — savoir qui n'est pas à jour.
//
// # Ce que le core NE fait PAS de ces valeurs
//
// Il ne les interprète jamais : aucun refus, aucun seuil, aucune comparaison.
// Elles sont stockées et affichées, rien de plus.
//
// C'est l'arbitrage du point 39, et il tient à une chose : une règle de
// comparaison de versions se trompe sur les cas limites, et se tromper ici
// voudrait dire fermer la porte à un parc dont le seul outil de réparation est
// l'agent qu'on vient de refuser.

// LongueurMaxVersion borne ce qu'on accepte d'écrire en base.
//
// La colonne fait 64 caractères. Une valeur plus longue serait tronquée par
// MySQL — silencieusement en mode non strict, ce qui donnerait une version
// coupée au milieu et donc fausse. On tronque nous-mêmes, et on le sait.
const LongueurMaxVersion = 64

// VersionsDeLInventaire extrait les deux versions d'un contenu 02_12 découpé.
//
// Rend deux chaînes vides quand les lignes sont absentes : ce n'est pas une
// erreur, c'est un agent d'une version antérieure.
func VersionsDeLInventaire(lignes []string) (programme, sdk string) {
	if len(lignes) > 5 {
		programme = nettoyerVersion(lignes[5])
	}
	if len(lignes) > 6 {
		sdk = nettoyerVersion(lignes[6])
	}
	return programme, sdk
}

// nettoyerVersion borne et assainit une version reçue du réseau.
//
// La valeur vient d'un client authentifié, pas de confiance pour autant : elle
// finit dans une colonne et dans des vues d'administration. Les caractères de
// contrôle en sont écartés — un retour chariot dans une version ferait sauter
// une ligne au milieu d'un tableau de la CLI.
func nettoyerVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, v)

	if len(v) > LongueurMaxVersion {
		// Tronquée ICI plutôt que par la base. Une troncature côté MySQL est
		// silencieuse en mode non strict : on lirait une version coupée sans
		// jamais savoir qu'elle l'a été.
		v = v[:LongueurMaxVersion]
	}
	return v
}
