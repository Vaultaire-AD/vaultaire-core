package ldapbindunbind

import (
	"time"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/global/security/totp"
)

// Second facteur au bind LDAP.
//
// LDAP n'a pas de champ pour un code : le compte soumis au second facteur
// l'accole à son mot de passe — `motdepasse` suivi de `123456`. Voir
// ldapstorage.MFABypass pour le réglage qui lève l'exigence.

// longueurCode est la longueur d'un code TOTP.
const longueurCode = 6

// etatMFA décrit ce que le bind doit exiger d'un compte.
type etatMFA struct {
	// Lie : le second facteur s'applique au compte — posé par lui, ou imposé
	// par un de ses groupes.
	Lie bool
	// Secret : le secret TOTP enrôlé, vide si le compte n'a pas enrôlé.
	Secret string
}

// Dépendances, en variables pour les tests.
var (
	lireEtatMFA = func(user string) (etatMFA, error) {
		db := database.GetDatabase()
		state, err := dbauthpolicy.GetAuthState(db, user)
		if err != nil {
			return etatMFA{}, err
		}
		exige, err := dbauthpolicy.IsMFARequired(db, user)
		if err != nil {
			// IsMFARequired est fail-closed ; on garde sa décision ET on
			// remonte l'erreur, pour que le bind refuse plutôt que de deviner.
			return etatMFA{}, err
		}
		e := etatMFA{Lie: exige}
		if state.MFAEnabled && state.MFASecret != "" {
			e.Lie = true
			e.Secret = state.MFASecret
		}
		return e, nil
	}
	validerTOTP       = totp.Validate
	consommerCompteur = func(user string, c int64) (bool, error) {
		return dbauthpolicy.ConsumeMFACounter(database.GetDatabase(), user, c)
	}
	maintenant = time.Now
)

// separerCode coupe « motdepasse123456 » en mot de passe et code.
//
// Faux si la valeur est trop courte ou ne finit pas par six chiffres : le
// compte doit alors être refusé, sans même essayer le mot de passe entier —
// l'accepter reviendrait à rendre le code facultatif.
func separerCode(authentification string) (motDePasse, code string, ok bool) {
	if len(authentification) <= longueurCode {
		return "", "", false
	}
	coupe := len(authentification) - longueurCode
	code = authentification[coupe:]
	for _, r := range code {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return authentification[:coupe], code, true
}

// verifierCode valide le code et le consomme (anti-rejeu, même compteur que le
// portail et la catégorie 08). Rend une raison de refus, vide si accepté.
func verifierCode(user, secret, code string) string {
	compteur, ok := validerTOTP(secret, code, maintenant())
	if !ok {
		return "code de second facteur invalide"
	}
	consomme, err := consommerCompteur(user, compteur)
	if err != nil {
		return "compteur du second facteur illisible : " + err.Error()
	}
	if !consomme {
		return "code de second facteur déjà utilisé"
	}
	return ""
}
