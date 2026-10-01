// Package compte provisionne le compte Windows local d'un utilisateur du
// domaine.
//
// # Pourquoi un compte LOCAL, et pas une identité Windows complète
//
// Windows n'ouvre de session qu'avec une identité qu'il connaît : un compte
// local, ou un compte d'un domaine Active Directory auquel la machine est
// jointe. Vaultaire n'est pas un domaine AD, et le devenir demanderait de
// parler Kerberos et LDAP comme un contrôleur de domaine — un autre projet.
//
// La V1 prend donc le chemin qu'utilisent les fournisseurs d'identité tiers :
// le core vérifie le mot de passe, et l'agent CRÉE (ou met à jour) un compte
// local portant ce même mot de passe. Windows ouvre ensuite une session
// ordinaire avec ce compte. Le mot de passe local reste ainsi le miroir de
// celui du domaine, changé à chaque connexion réussie.
//
// Ce que cela implique, et qui est assumé en V1 : le mot de passe d'un compte
// dont l'utilisateur ne se connecte plus reste celui de sa dernière connexion.
// Une révocation côté core n'efface pas le compte local — elle empêche la
// PROCHAINE authentification, pas l'usage d'un mot de passe déjà connu. Le
// traitement des révocations sur Windows viendra avec les GPO.
package compte

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// LongueurMaxCompte : Windows borne un nom de compte local à 20 caractères.
const LongueurMaxCompte = 20

// longueurEmpreinte est la taille du suffixe distinctif.
const longueurEmpreinte = 6

// NomLocal rend le nom du compte Windows local pour un utilisateur du domaine.
//
//	alice@test.fr          ->  alice-1f4b2c
//	jean.dupont@acme.lan   ->  jean.dupont-8a0f31
//	un.nom.tres.long@x.fr  ->  un.nom.tres.-4c9e07
//
// # Trois contraintes, une seule solution
//
//  1. Windows refuse « @ » dans un nom de compte local, ainsi que
//     « " / \ [ ] : ; | = , + * ? < > ». Le nom du domaine ne peut donc pas
//     être conservé tel quel.
//  2. Le nom est borné à 20 caractères. Beaucoup d'identifiants du domaine,
//     une fois tronqués, deviennent identiques.
//  3. Un compte LOCAL préexistant peut déjà porter le nom court. « alice » sur
//     le poste n'est pas « alice@test.fr » : écrire le mot de passe du domaine
//     dans le compte local d'un administrateur de la machine serait une prise
//     de contrôle, pas un provisionnement.
//
// D'où le suffixe : six caractères tirés de l'empreinte du nom COMPLET. Il rend
// le nom déterministe (le même utilisateur retombe toujours sur le même compte,
// connexion après connexion), distinct entre deux domaines, et impossible à
// confondre avec un compte local créé à la main.
func NomLocal(utilisateur string) string {
	// Tout en minuscules, empreinte comprise : Windows ne distingue pas
	// « Alice » de « alice », et le core non plus. Garder la casse ferait
	// naître un SECOND compte local — donc un second profil, un bureau vide —
	// à la première connexion où l'utilisateur tape son nom autrement.
	utilisateur = strings.ToLower(utilisateur)

	somme := sha256.Sum256([]byte(utilisateur))
	empreinte := hex.EncodeToString(somme[:])[:longueurEmpreinte]

	base := utilisateur
	if i := strings.LastIndex(base, "@"); i > 0 {
		base = base[:i]
	}
	base = nettoyer(base)

	maxBase := LongueurMaxCompte - longueurEmpreinte - 1 // le tiret
	if len(base) > maxBase {
		base = base[:maxBase]
	}
	// Un nom Windows ne peut pas finir par un point ; la troncature peut en
	// produire un.
	base = strings.TrimRight(base, ".")
	if base == "" {
		base = "vlt"
	}
	return base + "-" + empreinte
}

// caracteresInterdits liste ce que Windows refuse dans un nom de compte.
const caracteresInterdits = `"/\[]:;|=,+*?<>@`

// nettoyer ne garde que ce qui est sûr, et remplace le reste par un point bas.
//
// Liste blanche plutôt que suppression des caractères interdits : le jeu
// autorisé par Windows dépend de la version et de la casse du système, et une
// liste noire qui se trompe donne un appel système en échec avec un code
// numérique — là où une liste blanche donne un nom laid mais qui marche.
func nettoyer(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '.' || r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}

// Commentaire est posé sur le compte local créé.
//
// Il sert à RECONNAÎTRE les comptes de l'agent sur une machine : sans marque,
// personne ne peut dire lesquels viennent du domaine, et un ménage éventuel
// devrait deviner.
const Commentaire = "Compte provisionné par Vaultaire"

// DescriptionCompte rend le libellé posé sur le compte (champ « nom complet »).
func DescriptionCompte(utilisateur string) string {
	return fmt.Sprintf("%s (Vaultaire)", utilisateur)
}
