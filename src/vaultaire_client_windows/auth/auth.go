// Package auth pose la question au core et attend son verdict.
//
// # Le chemin, en une phrase
//
// L'agent ouvre une trame 03_01 dans le tunnel Ducky déjà établi — le mot de
// passe voyage DEDANS, comme sur les trois autres portes du serveur (portail,
// bind LDAP, chemin PAM) — et attend la réponse 03_02 (accepté) ou 03_03
// (refusé) sur un canal enregistré au nom de l'utilisateur.
//
// # Pourquoi c'est le même mécanisme que l'agent Linux
//
// Le registre d'attentes (`sshreq`) et le type de verdict (`pamstate.
// AuthResult`) viennent du module de l'agent Linux, importés tels quels. Les
// deux agents posent la même question au même serveur : une seconde
// implémentation n'aurait apporté qu'une seconde façon de se tromper sur ce
// qu'« accepté » veut dire — et c'est précisément là qu'un défaut coûte cher,
// puisqu'un zéro de structure lu sans précaution se lit comme un succès.
package auth

import (
	"fmt"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"

	"vaultaire_client/pamstate"
	"vaultaire_client/tools/sshreq"
)

// DelaiVerdict borne l'attente de la réponse du core.
//
// Sept secondes, comme le chemin PAM de l'agent Linux : c'est le délai au-delà
// duquel un utilisateur devant l'écran de connexion conclut que la machine est
// morte. Le dépassement est rendu comme tel, et non comme un refus : il ne dit
// rien du mot de passe.
var DelaiVerdict = 7 * time.Second

// Verdict est ce que l'agent conclut d'une tentative.
type Verdict struct {
	Accepte        bool
	Administrateur bool
	// Indisponible : aucun tunnel vers un core. À distinguer d'un refus.
	Indisponible bool
	Delai        bool
	Motif        string

	// Avertissement est le message que le CORE demande d'afficher quand la
	// session s'ouvre (TO-DO 99) : mot de passe provisoire, expiration
	// prochaine. Vide le plus souvent.
	//
	// Il accompagne une acceptation, jamais un refus : le motif d'un refus
	// voyage dans Motif.
	Avertissement string
}

// Authentifier envoie le mot de passe au core et attend le verdict.
//
// Le mot de passe n'est ni journalisé, ni conservé : il ne sort de cette
// fonction que dans la trame.
func Authentifier(utilisateur, motDePasse, code string) Verdict {
	// La session EXISTANTE, sans jamais attendre qu'elle s'ouvre.
	//
	// Le chemin habituel du socle (OpenVaultaireDefaultSession) démarre le
	// tunnel s'il manque, puis attend jusqu'à CENT SECONDES. Devant un écran de
	// connexion, c'est une machine qui a l'air morte — et le tunnel se
	// rétablit de toute façon tout seul, la supervision s'en charge en fond.
	// Mieux vaut répondre « indisponible » en un instant : l'utilisateur
	// réessaie, et la tentative suivante trouvera le tunnel.
	sess := stosession.SessionsUser.GetValidVaultaireSession()
	if sess == nil || sess.DuckySession == nil {
		// Le tunnel est en cours de rétablissement, ou aucun core n'est
		// joignable. Le dire franchement : un refus ferait chercher du côté du
		// mot de passe, et la supervision relance la connexion de son côté.
		logs.Write_log("ERROR", fmt.Sprintf(
			"authentification impossible pour %s : aucune session machine", utilisateur))
		return Verdict{Indisponible: true, Motif: "aucun core joignable"}
	}

	// L'attente est enregistrée AVANT l'envoi : la réponse arrive sur la
	// goroutine de lecture du tunnel, qui n'attend personne. Enregistrer après
	// laisserait une fenêtre où le verdict serait jeté faute de destinataire.
	attente := make(chan pamstate.AuthResult, 1)
	sshreq.Register(utilisateur, attente)
	defer sshreq.Remove(utilisateur)

	// Le code de second facteur voyage EN QUEUE, sur une ligne préfixée
	// (TO-DO 95) : un core resté à l'ancienne version lit les deux premières
	// lignes et ignore le reste, au lieu de prendre le code pour autre chose.
	//
	// La ligne n'est ajoutée que si la tuile a envoyé un code : son ABSENCE dit
	// au core « agent ancien », et en fabriquer une vide ferait passer cet agent
	// pour à jour alors qu'il ne demande rien à l'utilisateur.
	contenu := []string{utilisateur, motDePasse}
	if code != "" {
		contenu = append(contenu, PrefixeOTP+code)
	}

	trame := sendmessage.BuildClientTrame("03_01", "serveur_central",
		string(sess.DuckySession.SessionKey), "vaultaire", storage.Computeur_ID,
		contenu...)
	sendmessage.SendMessage(trame, sess.DuckySession)

	select {
	case resultat, recu := <-attente:
		// Le second retour COMPTE : lire un canal fermé rend le zéro du type,
		// sans erreur, et ce zéro s'est déjà lu comme un succès dans l'agent
		// Linux — au point de réécrire /etc/shadow avec le mot de passe essayé.
		if !recu || !resultat.Accepte {
			logs.Write_log("WARNING", "authentification refusée par le core pour "+utilisateur)
			return Verdict{Motif: "refusé par le core"}
		}
		logs.Write_log("INFO", fmt.Sprintf(
			"authentification acceptée pour %s (administrateur : %t)", utilisateur, resultat.IsAdmin))
		return Verdict{Accepte: true, Administrateur: resultat.IsAdmin,
			Avertissement: resultat.Avertissement}

	case <-time.After(DelaiVerdict):
		logs.Write_log("ERROR", fmt.Sprintf(
			"aucune réponse du core en %s pour %s", DelaiVerdict, utilisateur))
		return Verdict{Delai: true, Motif: "le core n'a pas répondu"}
	}
}

// Raccorde dit si un tunnel vers un core est utilisable maintenant.
//
// Sert à répondre à la requête « etat » du Credential Provider, qui l'affiche
// AVANT que l'utilisateur ne tape son mot de passe : « service indisponible »
// au premier écran vaut mieux qu'un refus après la saisie.
func Raccorde() bool {
	// Regarde, n'attend pas : cette réponse s'affiche pendant que l'utilisateur
	// choisit sa tuile.
	sess := stosession.SessionsUser.GetValidVaultaireSession()
	return sess != nil && sess.DuckySession != nil
}

// SeparerDomaine rend (compte, domaine) à partir de « alice@test.fr ».
//
// Le domaine décide de ce que le core cherche : un nom sans domaine ne désigne
// aucun compte de l'annuaire, et le core le refuse. L'agent le contrôle ici
// pour pouvoir le DIRE — « il manque le domaine » est une réponse utile devant
// un écran de connexion, « refusé » ne l'est pas.
func SeparerDomaine(utilisateur string) (string, string) {
	i := strings.LastIndex(utilisateur, "@")
	if i <= 0 || i == len(utilisateur)-1 {
		return utilisateur, ""
	}
	return utilisateur[:i], utilisateur[i+1:]
}
