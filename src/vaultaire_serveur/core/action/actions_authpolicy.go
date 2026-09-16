package action

import (
	"fmt"
	"strconv"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
)

// Politique d'expiration des mots de passe.
//
// # Pourquoi cette action exige le groupe protégé
//
// La page web était déjà réservée aux membres du groupe protégé
// (requireSuperadminPage) et non contrôlée par une clé RBAC. La raison tient :
// une politique d'expiration s'applique à TOUS les comptes de l'annuaire, quel
// que soit leur domaine. Ce n'est pas un réglage qui se délègue par périmètre.
//
// C'est le même raisonnement que pour les certificats et les restrictions GPO.

// Bornes de saisie.
//
// Reprises de la couche base, qui reste la seule à faire foi : la validation
// qui compte est celle de SetPasswordPolicy, parce qu'elle s'applique aussi à
// une requête forgée qui n'emprunterait pas ce chemin.
const (
	politiqueMaxAgeLimite = 3650
	politiqueWarnLimite   = 365
)

// EnregistrerActionsPolitiqueMotDePasse ajoute l'action au registre.
func EnregistrerActionsPolitiqueMotDePasse(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:             "authpolicy.set_password_policy",
		ExigeSuperadmin: true,
		Portee:          PorteeGlobale,
		Resume:          "règle l'expiration des mots de passe (réservé au groupe protégé)",
		Executer:        reglerPolitiqueMotDePasse,
	})
}

func reglerPolitiqueMotDePasse(a Appelant, p Params) (Resultat, error) {
	maxAge, err := entierBorne(p.Get("max_age_days"), "durée de validité", 0, politiqueMaxAgeLimite)
	if err != nil {
		return Resultat{}, err
	}
	preavis, err := entierBorne(p.Get("warn_days"), "préavis", 0, politiqueWarnLimite)
	if err != nil {
		return Resultat{}, err
	}

	// Un préavis plus long que la validité n'a pas de sens : l'utilisateur
	// serait averti avant même que son mot de passe ne soit valide. Ni la page
	// ni le CLI ne le vérifiaient — la base acceptait la combinaison, et
	// l'avertissement s'affichait en permanence.
	if maxAge > 0 && preavis >= maxAge {
		return Resultat{}, fmt.Errorf(
			"préavis invalide : %d jours d'avertissement pour une validité de %d jours — "+
				"l'avertissement serait affiché en permanence", preavis, maxAge)
	}

	politique := dbauthpolicy.PasswordPolicySettings{MaxAgeDays: maxAge, WarnDays: preavis}
	if err := dbauthpolicy.SetPasswordPolicy(database.GetDatabase(), politique, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de l'enregistrement de la politique : %w", err)
	}

	if !politique.Enabled() {
		return Resultat{Message: "Politique enregistrée : les mots de passe n'expirent plus."}, nil
	}

	// Le message dit ce qui va arriver aux comptes anciens. Activer une
	// politique à 90 jours sur un annuaire qui n'en avait aucune expire d'un
	// coup tout ce qui n'a pas été changé depuis trois mois : c'est le
	// comportement correct, mais il ne doit pas être une surprise.
	return Resultat{
		Message: "Politique enregistrée. Les comptes dont le mot de passe date de plus de " +
			strconv.Itoa(politique.MaxAgeDays) + " jours sont expirés dès maintenant.",
		Donnees: map[string]int{"max_age_days": maxAge, "warn_days": preavis},
	}, nil
}
