package passwordpolicy

import (
	"database/sql"
	"fmt"
	"time"

	dbauthpolicy "vaultaire/core/database/db_authpolicy"
)

// Le mot de passe à usage unique, à changement obligatoire — TO-DO 99.
//
// # Ce à quoi il répond
//
// Le compte d'amorçage naissait avec le mot de passe publié dans le dépôt Git
// du produit, sans aucun drapeau « à changer », et `password_changed_at` posée
// au jour même : il n'était même pas expiré. Mais le besoin dépasse ce cas —
// c'est aussi ce qu'il faut pour créer un compte, pour le dépanner, et pour
// qu'un administrateur réinitialise le mot de passe de quelqu'un sans le
// connaître ensuite.
//
// # Le comportement, et pourquoi il n'enferme PAS l'utilisateur dehors
//
// Un mot de passe provisoire OUVRE LA SESSION. Sur le portail, sur SSH, sur
// GDM, sur Windows. L'utilisateur est simplement AVERTI, à chaque connexion,
// que son mot de passe doit être changé — et le changement se fait sur le
// portail.
//
// C'est un choix, et il se justifie : le chemin PAM est celui par lequel on se
// connecte vraiment. Y refuser la session tant que le mot de passe n'a pas été
// changé demanderait de changer son mot de passe… sans pouvoir ouvrir de
// session pour le faire. Un employé dont le poste est la seule porte d'entrée
// serait enfermé dehors par la mesure censée le protéger.
//
// # L'ÉCHÉANCE, elle, refuse
//
// Un mot de passe provisoire porte une date au-delà de laquelle il ne vaut plus
// rien. Passée cette date, il est traité EXACTEMENT comme un mot de passe
// expiré — même état, même refus, mêmes chemins. Ce n'est pas une
// approximation : un provisoire périmé et un mot de passe trop vieux posent le
// même problème et appellent la même réponse, et réutiliser l'état existant
// évite d'écrire une seconde fois, dans quatre handlers, la logique de refus
// qui y est déjà.
//
// C'est aussi ce qui fait que LDAP en hérite sans qu'une ligne y soit écrite.

// DureeProvisoireDefaut borne la validité d'un mot de passe provisoire.
//
// Vingt-quatre heures : assez pour qu'un mot de passe communiqué en fin de
// journée serve le lendemain matin, assez peu pour qu'un mot de passe oublié
// dans un courriel ou un ticket ne soit plus utilisable la semaine suivante.
const DureeProvisoireDefaut = 24 * time.Hour

// Obligation dit ce qu'il faut faire d'un mot de passe provisoire.
type Obligation struct {
	// ADemander : le mot de passe doit être changé. La session est tout de même
	// accordée tant que Perime est faux.
	ADemander bool

	// Perime : l'échéance est dépassée. Le mot de passe ne vaut plus rien, et
	// les chemins qui refusent un mot de passe expiré refusent celui-ci.
	Perime bool

	// Echeance est la date au-delà de laquelle le provisoire ne vaut plus.
	// Nulle quand il n'y en a pas — le changement reste alors obligatoire, sans
	// limite de temps.
	Echeance time.Time
}

// EvaluerObligation applique la règle. Fonction pure.
func EvaluerObligation(mustChange bool, echeance time.Time, aEcheance bool, now time.Time) Obligation {
	if !mustChange {
		return Obligation{}
	}
	o := Obligation{ADemander: true}
	if aEcheance {
		o.Echeance = echeance
		// `After` et non `!Before` : à la seconde exacte de l'échéance, le mot de
		// passe vaut encore. Le contraire ferait dépendre le résultat de
		// l'arrondi de l'horloge, sur une comparaison que deux serveurs du
		// cluster n'évaluent pas à la même milliseconde.
		o.Perime = now.After(echeance)
	}
	return o
}

// ObligationDepuisEtat lit l'obligation d'un état déjà chargé.
//
// À préférer partout où AuthState a déjà été lu — c'est le cas de tous les
// chemins d'authentification, qui le lisent pour le second facteur.
func ObligationDepuisEtat(state dbauthpolicy.AuthState) Obligation {
	return EvaluerObligation(state.MustChangePassword,
		state.ProvisionalUntil, state.HasProvisionalUntil, time.Now())
}

// MessageDeChangement rend l'avertissement à présenter à l'utilisateur.
//
// # Pourquoi cette fonction existe, plutôt qu'un texte dans chaque façade
//
// Le même avertissement doit atteindre quatre endroits qui ne se ressemblent
// pas : une page web, une invite SSH, l'écran de connexion de GDM et la tuile
// Windows. Quatre textes auraient divergé à la première correction, et trois
// seraient restés en anglais.
//
// Il est volontairement COURT et sans mise en forme : il traverse un canal qui
// l'affiche tel quel, sur une seule ligne, dans un terminal qui n'a pas
// forcément de couleurs.
func MessageDeChangement(o Obligation) string {
	if !o.ADemander {
		return ""
	}
	if o.Perime {
		return "Votre mot de passe provisoire a expiré. Demandez-en un nouveau à votre administrateur."
	}
	if o.Echeance.IsZero() {
		return "Votre mot de passe est provisoire : changez-le sur le portail Vaultaire."
	}
	return fmt.Sprintf(
		"Votre mot de passe est provisoire et cesse de fonctionner le %s : "+
			"changez-le sur le portail Vaultaire.",
		o.Echeance.Format("02/01/2006 à 15:04"))
}

// MessageDePreavis rend l'avertissement d'expiration prochaine.
//
// Même canal, même format, autre cause — c'est ce qui rend le dispositif du
// point 99 réutilisable pour le préavis du point d'expiration : jusqu'ici,
// l'avertissement des N derniers jours n'était affiché que sur le portail,
// c'est-à-dire à l'endroit où l'utilisateur ne va justement pas.
func MessageDePreavis(s Status) string {
	if !s.ShouldWarn() {
		return ""
	}
	if s.DaysUntilExpiry <= 1 {
		return "Votre mot de passe expire demain : changez-le sur le portail Vaultaire."
	}
	return fmt.Sprintf("Votre mot de passe expire dans %d jours : "+
		"changez-le sur le portail Vaultaire.", s.DaysUntilExpiry)
}

// AvertissementDeConnexion compose LA ligne à présenter, quelle qu'en soit la
// cause.
//
// Une seule ligne, et une seule fonction pour la produire : un utilisateur dont
// le mot de passe est à la fois provisoire et bientôt expiré n'a pas besoin de
// deux messages, il a besoin de savoir qu'il doit aller sur le portail. Le
// provisoire l'emporte parce qu'il est le plus pressant — et qu'il porte une
// échéance en heures, là où le préavis en porte une en jours.
func AvertissementDeConnexion(o Obligation, s Status) string {
	if msg := MessageDeChangement(o); msg != "" {
		return msg
	}
	return MessageDePreavis(s)
}

// StatutAvecProvisoire fusionne l'expiration ordinaire et l'échéance d'un
// provisoire.
//
// # C'est ici que la réutilisation se fait
//
// Un provisoire périmé devient un `StateExpired` ordinaire. Les quatre chemins
// qui savent déjà refuser un mot de passe expiré — bind LDAP, Ducky/PAM,
// portail, services — le refusent donc sans qu'une ligne y soit ajoutée, et
// sans qu'on puisse en oublier un.
func StatutAvecProvisoire(s Status, o Obligation) Status {
	if o.Perime {
		s.State = StateExpired
		s.Exempt = false
	}
	return s
}

// MarquerProvisoire pose le drapeau et l'échéance sur un compte.
//
// Appelée après une écriture de mot de passe PAR UN TIERS : création d'un
// compte, réinitialisation par un administrateur, amorçage. Jamais après un
// changement par le titulaire — celui-là LÈVE le drapeau.
//
// `duree` à zéro pose le drapeau sans échéance : le changement reste
// obligatoire, le mot de passe ne périme pas.
func MarquerProvisoire(db *sql.DB, username string, duree time.Duration) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	if duree <= 0 {
		_, err := db.Exec(`UPDATE users
			SET must_change_password = TRUE, provisional_password_until = NULL
			WHERE username = ?`, username)
		return err
	}
	_, err := db.Exec(`UPDATE users
		SET must_change_password = TRUE, provisional_password_until = ?
		WHERE username = ?`, time.Now().Add(duree), username)
	return err
}

// LeverProvisoire retire le drapeau après un changement par le titulaire.
//
// Les deux colonnes sont remises ensemble : laisser une échéance derrière un
// drapeau levé ferait qu'un futur marquage sans durée hériterait de l'ancienne
// date — donc naîtrait périmé.
func LeverProvisoire(db *sql.DB, username string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	_, err := db.Exec(`UPDATE users
		SET must_change_password = FALSE, provisional_password_until = NULL
		WHERE username = ?`, username)
	return err
}
