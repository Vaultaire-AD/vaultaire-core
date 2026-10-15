package compte

import "fmt"

// Traduction des codes de netapi32.
//
// # Pourquoi ce fichier n'est pas sous `//go:build windows`
//
// Il ne contient aucun appel système : ce sont des nombres et des phrases. Le
// laisser compiler partout le rend éprouvable sans machine Windows — et c'est
// précisément la partie qu'on veut éprouver, puisqu'un message d'erreur ne se
// vérifie qu'en le lisant.

// Codes rendus par netapi32, et par NetUserAdd en particulier.
const (
	// ErrMotDePasseRefuse est NERR_PasswordTooShort.
	//
	// Le nom ment : Windows le rend pour TOUT refus de la politique de mot de
	// passe — longueur minimale, exigence de complexité, ou réutilisation d'un
	// mot de passe encore dans l'historique. C'est ce qui a coûté une session
	// de recette : le code fait chercher une longueur, alors que la cause peut
	// être ailleurs.
	ErrMotDePasseRefuse = 2245
	// ErrMotDePasseTropRecent est NERR_PasswordTooRecent : l'âge minimal du
	// mot de passe n'est pas écoulé.
	ErrMotDePasseTropRecent = 2246
	// ErrCompteExiste est NERR_UserExists.
	ErrCompteExiste = 2224
	// ErrCompteInconnu est NERR_UserNotFound.
	ErrCompteInconnu = 2221
	// ErrAccesRefuse est ERROR_ACCESS_DENIED : l'agent ne tourne pas en SYSTEM.
	ErrAccesRefuse = 5
	// ErrParametreInvalide est ERROR_INVALID_PARAMETER.
	ErrParametreInvalide = 87
)

// ParametreInconnu est PARM_ERROR_UNKNOWN : Windows ne sait pas dire QUEL champ
// il refuse. C'est la valeur rendue dans la quasi-totalité des cas, et
// l'afficher telle quelle — 4294967295 — donne un nombre qui ressemble à une
// information et n'en est pas.
const ParametreInconnu = 0xFFFFFFFF

// ErreurNetapi explique un code de netapi32 en français, avec ce qu'il faut
// faire.
//
// # Ce que le message doit dire, et ce qu'il disait
//
// « NetUserAdd : code 2245 (paramètre 4294967295) » est exact et inutilisable :
// il faut connaître netapi32 pour le lire, et le second nombre ne veut rien
// dire. Ce que la personne devant l'écran doit comprendre, c'est QUI refuse —
// le poste, pas Vaultaire — et ce qu'elle peut y faire.
func ErreurNetapi(appel string, code, parametre uint32) error {
	if code == 0 {
		return nil
	}

	detail := ""
	if parametre != ParametreInconnu {
		detail = fmt.Sprintf(" (champ %d)", parametre)
	}

	switch code {
	case ErrMotDePasseRefuse:
		// Depuis le TO-DO 195, le mot de passe local est un secret de 32
		// caractères tiré par l'agent, les quatre familles présentes : une
		// politique ordinaire l'accepte toujours. Un refus vient donc d'une
		// politique inhabituelle — longueur exigée au-delà de 32, filtre de
		// mots de passe tiers. install.ps1 n'assouplit plus rien.
		return fmt.Errorf("la politique de mot de passe de CE POSTE refuse le secret de "+
			"l'agent, pourtant long de 32 caractères et complexe (longueur minimale, complexité "+
			"exigée, ou mot de passe encore dans l'historique) — code %d. Ce n'est pas Vaultaire "+
			"qui refuse : vérifiez « net accounts » et la stratégie de sécurité locale "+
			"(secpol.msc), ou un filtre de mots de passe installé sur le poste", code)

	case ErrMotDePasseTropRecent:
		return fmt.Errorf("la politique du poste interdit de changer ce mot de passe si tôt "+
			"(âge minimal non écoulé) — code %d. Voir « net accounts /minpwage »", code)

	case ErrAccesRefuse:
		return fmt.Errorf("accès refusé par Windows lors de %s — code %d. L'agent doit "+
			"tourner sous le compte SYSTEM : vérifiez « sc qc VaultaireAgent »", appel, code)

	case ErrCompteInconnu:
		return fmt.Errorf("compte local introuvable lors de %s — code %d", appel, code)

	case ErrParametreInvalide:
		return fmt.Errorf("%s : paramètre refusé par Windows — code %d%s", appel, code, detail)

	default:
		return fmt.Errorf("%s : code %d%s", appel, code, detail)
	}
}
