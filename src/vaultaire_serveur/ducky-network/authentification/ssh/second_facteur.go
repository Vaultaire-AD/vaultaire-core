package sshclient

import (
	"database/sql"
	"strings"
	"time"

	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbsettings "vaultaire/core/database/db_settings"
	"vaultaire/core/global/security/totp"
	"vaultaire/core/logs"
)

// Le second facteur sur le chemin Ducky — TO-DO 95.
//
// # Ce qui manquait
//
// `grep -rn "mfa\|totp" ducky-network/authentification/` ne rendait RIEN. Le
// second facteur était appliqué sur le portail web, au bind LDAP et sur les
// trames 08 (services du cluster) — mais pas sur le canal qui ouvre les
// sessions des postes du parc, c'est-à-dire le plus utilisé de tous.
//
// Un compte marqué `mfa_required` dont le mot de passe fuite était donc bloqué
// sur le portail et ouvrait une session SSH sur n'importe quelle machine. Pire :
// `MFA_et_Expiration.md` annonçait l'expiration sur « tous les chemins,
// Ducky/PAM compris » et ne signalait nulle part que le second facteur, lui,
// n'y était pas.
//
// # LDAP n'est pas concerné, et ne doit pas l'être
//
// Le protocole LDAP n'a pas de place pour un second facteur : le bind ne porte
// qu'un DN et un mot de passe. L'arrangement en vigueur — le code accolé au mot
// de passe, plus `ldap.mfa_bypass` — reste ce qu'il est. Rien n'y est touché.
//
// # La convention « 0000 »
//
// Le code voyage sur TOUTES les ouvertures de session, y compris celles des
// comptes qui n'ont pas de second facteur. L'invite dit quoi taper dans ce cas :
// `0000`.
//
// Côté core, quand le compte n'a PAS de second facteur, `0000` est la seule
// valeur acceptée — toute autre est refusée. Ce n'est pas du formalisme : un
// client qui envoie un vrai code à un compte sans second facteur ne fait pas ce
// qu'on croit, et l'accepter en silence masquerait soit un défaut de l'agent,
// soit quelqu'un qui sonde la porte.
//
// # Pourquoi une invite plutôt qu'un code accolé au mot de passe
//
// C'est la recette du bind LDAP, et elle y est subie faute de mieux. Elle a deux
// défauts qu'on peut éviter ici : un mot de passe qui finit par six chiffres
// devient ambigu, et le code se retrouve dans la même variable que le mot de
// passe — donc dans les mêmes journaux, les mêmes tampons et les mêmes
// gestionnaires de mots de passe.

// PrefixeOTP ouvre la ligne du code de second facteur dans la trame 03_01.
//
// EN QUEUE et PRÉFIXÉE, comme « groups: », « refresh: », « sig: » et
// « notice: ». C'est la recette de compatibilité du produit : un core resté à
// l'ancienne version lit les deux premières lignes et ignore le reste, au lieu
// de prendre le code pour autre chose ; un agent resté à l'ancienne version
// n'envoie simplement pas la ligne.
const PrefixeOTP = "otp:"

// LongueurMaxOTP borne ce qu'on accepte de lire.
//
// Un code TOTP fait six chiffres ; la borne est large pour laisser passer un
// format futur, et serrée pour qu'une ligne de mille caractères ne traverse pas
// la vérification. Même borne que la catégorie 08.
const LongueurMaxOTP = 16

// CodeSansSecondFacteur est ce que tape quelqu'un qui n'a pas de second facteur.
const CodeSansSecondFacteur = "0000"

// CleMFADuckyExigee est le réglage poussé qui ferme la porte aux agents anciens.
const CleMFADuckyExigee = "mfa_ducky_required"

const (
	mfaDuckyExigeeDefaut = 0
	mfaDuckyExigeeMin    = 0
	mfaDuckyExigeeMax    = 1
)

// MFADuckyExigee dit si un agent doit obligatoirement envoyer un code.
//
// # Pourquoi ce réglage existe
//
// Un agent d'une version antérieure n'envoie AUCUN code. Le core doit donc
// l'accepter, sinon la mise à jour du core coupe l'accès à tout le parc d'un
// coup — y compris à la machine depuis laquelle on administre.
//
// Mais tant qu'il l'accepte, le second facteur se contourne avec un vieil
// agent : il suffit d'en installer un. Le réglage tranche le nœud — on met le
// parc à jour, PUIS on l'active, et il se retire en une commande si quelque
// chose se passe mal.
//
// C'est le dispositif du point 52 (signature des GPO), repris tel quel parce
// qu'il répond au même problème : une exigence qu'on ne peut pas activer d'un
// coup et dont on doit pouvoir sortir.
func MFADuckyExigee(db *sql.DB) bool {
	return dbsettings.GetInt(db, CleMFADuckyExigee,
		mfaDuckyExigeeMin, mfaDuckyExigeeMax, mfaDuckyExigeeDefaut) == 1
}

// DefinirMFADuckyExigee écrit le réglage.
func DefinirMFADuckyExigee(db *sql.DB, exigee bool, parQui string) error {
	valeur := 0
	if exigee {
		valeur = 1
	}
	return dbsettings.SetInt(db, CleMFADuckyExigee, valeur,
		mfaDuckyExigeeMin, mfaDuckyExigeeMax, parQui)
}

// LireCodeOTP extrait le code de la trame, par PRÉFIXE et jamais par rang.
//
// Le deuxième retour distingue « pas de ligne du tout » — un agent ancien — de
// « ligne présente et vide », qui est un agent à jour dont l'utilisateur n'a
// rien tapé. Les deux n'appellent pas la même réponse : le premier est un cas de
// migration, le second est une saisie vide.
func LireCodeOTP(lignes []string) (code string, present bool) {
	for _, l := range lignes {
		if !strings.HasPrefix(l, PrefixeOTP) {
			continue
		}
		code = strings.TrimSpace(strings.TrimPrefix(l, PrefixeOTP))
		if len(code) > LongueurMaxOTP {
			// Tronqué plutôt que refusé ici : la décision de refuser appartient à
			// la vérification, qui sait dire pourquoi. Tronquer garantit
			// seulement qu'une ligne démesurée ne traverse pas la suite.
			code = code[:LongueurMaxOTP]
		}
		return code, true
	}
	return "", false
}

// ResultatMFA dit ce que la vérification a conclu.
type ResultatMFA int

const (
	// MFAAccepte : la session peut continuer.
	MFAAccepte ResultatMFA = iota
	// MFARefuse : code faux, rejoué, ou valeur inattendue.
	MFARefuse
	// MFAManquant : aucun code envoyé alors qu'il en faut un.
	MFAManquant
	// MFAIndisponible : l'état du compte est illisible.
	MFAIndisponible
)

// VerifierSecondFacteur applique la règle. Rend le résultat et un motif pour le
// journal.
//
// # L'ordre des cas
//
//  1. Compte AVEC second facteur : le code est obligatoire et doit être valide,
//     puis consommé — l'anti-rejeu est celui du portail, partagé par toutes les
//     portes, donc un code observé ne sert qu'une fois où que ce soit.
//  2. Compte SANS second facteur, mais dont un groupe l'EXIGE : refus, avec un
//     motif qui dit d'aller l'enrôler. Le laisser passer viderait l'exigence de
//     groupe de son sens sur le chemin le plus utilisé.
//  3. Compte SANS second facteur : seul `0000` est accepté.
//
// # Le refus d'un code absent dépend du réglage
//
// Sans code du tout et sans second facteur sur le compte, on accepte tant que
// `mfa_ducky_required` est à zéro : c'est le cas d'un agent ancien, et le
// refuser couperait le parc à la mise à jour du core. Avec le réglage actif, on
// refuse — c'est précisément ce qu'il sert à décider.
func VerifierSecondFacteur(db *sql.DB, username, code string, present bool) (ResultatMFA, string) {
	etat, err := dbauthpolicy.GetAuthState(db, username)
	if err != nil {
		return MFAIndisponible, "état du second facteur illisible : " + err.Error()
	}

	exige, errExige := dbauthpolicy.IsMFARequired(db, username)
	if errExige != nil {
		// IsMFARequired est fail-closed : elle rend `true` en cas d'erreur. On le
		// journalise sans changer sa décision — ouvrir ici annulerait le
		// fail-closed qu'elle applique exprès.
		logs.Write_Log("ERROR",
			"SSH: exigence de second facteur illisible pour "+username+" : "+errExige.Error())
	}

	decision, motif := DeciderSecondFacteur(Entree{
		Actif:          etat.MFAEnabled && etat.MFASecret != "",
		ExigeParGroupe: exige,
		CodePresent:    present,
		Code:           code,
		ExigenceDucky:  MFADuckyExigee(db),
	})
	if decision != MFAVerifier {
		return decision.resultat(), motif
	}

	// La VÉRIFICATION elle-même : elle touche la cryptographie et la base, donc
	// elle vit hors de la décision — laquelle s'éprouve sans ni l'une ni l'autre.
	compteur, ok := totp.Validate(etat.MFASecret, code, maintenant())
	if !ok {
		return MFARefuse, "code de second facteur invalide"
	}
	// ANTI-REJEU. Le compteur est celui du portail : un code observé sur un
	// écran ne sert qu'une fois, sur toutes les portes du produit.
	consomme, errC := dbauthpolicy.ConsumeMFACounter(db, username, compteur)
	if errC != nil {
		return MFAIndisponible, "compteur de second facteur illisible : " + errC.Error()
	}
	if !consomme {
		return MFARefuse, "code de second facteur déjà utilisé"
	}
	return MFAAccepte, ""
}

// Entree est ce que la décision a besoin de savoir.
//
// Une structure plutôt que cinq paramètres booléens : à l'appel, cinq booléens
// dans le désordre se lisent tous pareil, et les inverser ne se voit pas.
type Entree struct {
	// Actif : le compte a un second facteur enrôlé ET validé.
	Actif bool
	// ExigeParGroupe : un groupe du compte impose le second facteur.
	ExigeParGroupe bool
	// CodePresent : la trame portait une ligne « otp: », vide ou non. Distingue
	// un agent ancien d'une saisie vide.
	CodePresent bool
	// Code est la valeur saisie.
	Code string
	// ExigenceDucky est le réglage poussé « mfa_ducky_required ».
	ExigenceDucky bool
}

// Decision est ce que la règle conclut, AVANT toute vérification cryptographique.
type Decision int

const (
	// MFAPasser : rien à vérifier, la session continue.
	MFAPasser Decision = iota
	// MFAVerifier : il y a un code à valider.
	MFAVerifier
	// MFARefuser : refus sans vérification.
	MFARefuser
	// MFAReclamer : aucun code alors qu'il en faut un.
	MFAReclamer
)

func (d Decision) resultat() ResultatMFA {
	switch d {
	case MFAPasser:
		return MFAAccepte
	case MFAReclamer:
		return MFAManquant
	default:
		return MFARefuse
	}
}

// DeciderSecondFacteur applique la règle. Fonction PURE : ni base, ni horloge,
// ni cryptographie.
//
// # L'ordre des cas
//
//  1. Compte AVEC second facteur : le code est obligatoire, quel que soit le
//     réglage de migration. Le réglage décide du sort des comptes ORDINAIRES
//     pendant la migration ; dispenser ceux qui ont activé le second facteur
//     reviendrait à désactiver la fonctionnalité pour ses seuls utilisateurs.
//  2. Compte SANS second facteur mais dont un groupe l'EXIGE : refus, avec un
//     motif qui dit d'aller l'enrôler. Le laisser passer viderait l'exigence de
//     groupe de son sens sur le chemin le plus utilisé du produit.
//  3. Compte SANS second facteur : seul « 0000 » est accepté.
func DeciderSecondFacteur(e Entree) (Decision, string) {
	switch {
	case e.Actif:
		if !e.CodePresent {
			return MFAReclamer, "code de second facteur requis, agent trop ancien pour l'envoyer"
		}
		if e.Code == "" {
			return MFAReclamer, "aucun code saisi"
		}
		return MFAVerifier, ""

	case e.ExigeParGroupe:
		return MFARefuser, "second facteur imposé par un groupe mais non enrôlé — " +
			"à faire sur le portail, /profil/mfa"

	default:
		if !e.CodePresent {
			if e.ExigenceDucky {
				return MFAReclamer, "aucun code envoyé et « " + CleMFADuckyExigee +
					" » est actif — agent à mettre à jour"
			}
			// Agent ancien, compte ordinaire : on accepte tant que la migration
			// n'est pas terminée. La refuser couperait tout le parc à la mise à
			// jour du core, machine d'administration comprise.
			return MFAPasser, ""
		}
		if e.Code == CodeSansSecondFacteur || e.Code == "" {
			return MFAPasser, ""
		}
		// Un vrai code pour un compte qui n'en a pas : on refuse plutôt que
		// d'ignorer. Cela signale soit un agent qui se trompe de compte, soit
		// quelqu'un qui sonde la porte — et l'ignorer masquerait les deux.
		return MFARefuser, "code de second facteur envoyé pour un compte qui n'en a pas"
	}
}

// maintenant est une variable pour que les tests fixent l'horloge sans
// dépendre de la seconde à laquelle ils tournent.
var maintenant = time.Now
