package database

import (
	"fmt"
	"regexp"
	"runtime"
	"strings"

	"vaultaire/core/logs"
)

// Deux niveaux de filtrage, et les confondre serait une erreur dans les deux
// sens.
//
// SanitizeInput est une liste NOIRE, appliquée à du texte libre : mots de passe,
// modèle de processeur (« Intel(R) Core(TM) i7 »), motifs d'expression
// régulière des restrictions GPO (« ^[a-z0-9._-]+\.service$ »), préfixes de
// chemin. Y interdire les espaces, parenthèses ou crochets casserait ces
// usages légitimes.
//
// SanitizeIdentifier est une liste BLANCHE, appliquée à ce qui nomme une entité :
// utilisateur, groupe, permission, identifiant de machine. Ces valeurs finissent
// dans des clauses WHERE, des DN LDAP, des chemins de fichiers et des noms de
// groupes POSIX. Rien qui ressemble à un espace, une parenthèse, un crochet ou
// un chevron n'y a sa place, et une liste blanche est la seule forme de
// filtrage qui n'oublie rien : ce qui n'est pas explicitement autorisé est
// refusé, y compris les caractères auxquels personne n'a encore pensé.

// unsafeChars sont les caractères refusés partout, y compris dans le texte
// libre : guillemets, point-virgule et caractères de contrôle.
var unsafeChars = regexp.MustCompile(`['";\n\r\t\x00\x1a]`)

// identifierRe décrit la forme acceptée d'un identifiant.
//
// Lettres, chiffres, point, tiret, souligné, arobase — de quoi écrire
// « admin », « admin@vaultaire.fr », « compta.vaultaire.fr », « poste-042 ».
// La longueur est bornée pour éviter qu'une valeur démesurée ne se propage dans
// des journaux ou des noms de fichiers.
var identifierRe = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,128}$`)

// SanitizeInput refuse les caractères dangereux dans du texte libre.
//
// Ne remplace pas les requêtes préparées et n'a jamais prétendu le faire : c'est
// une seconde barrière, utile là où une valeur ne peut pas être passée en
// paramètre (nom de colonne, par exemple).
func SanitizeInput(inputs ...string) error {
	functionSource := callerName()

	for _, input := range inputs {
		if unsafeChars.MatchString(input) {
			logs.WriteLog("SQL_Injection", fmt.Sprintf("Appel depuis %s", functionSource))
			return fmt.Errorf("injection SQL détectée : caractères dangereux trouvés dans l'entrée : %s", input)
		}
	}
	return nil
}

// SanitizeIdentifier n'accepte qu'un identifiant bien formé.
//
// À utiliser pour tout ce qui NOMME une entité. Pour du texte libre — mot de
// passe, description, contenu de fichier déployé, motif d'expression
// régulière — utiliser SanitizeInput : cette fonction-ci les refuserait tous.
func SanitizeIdentifier(inputs ...string) error {
	functionSource := callerName()

	for _, input := range inputs {
		// La valeur vide est traitée à part : le message « identifiant vide »
		// est autrement plus parlant qu'un rejet de forme, et c'est une erreur
		// d'appel fréquente (champ de formulaire non rempli).
		if strings.TrimSpace(input) == "" {
			logs.WriteLog("SQL_Injection", fmt.Sprintf("Identifiant vide depuis %s", functionSource))
			return fmt.Errorf("identifiant vide")
		}
		if !identifierRe.MatchString(input) {
			logs.WriteLog("SQL_Injection", fmt.Sprintf(
				"Identifiant malformé %q depuis %s", input, functionSource))
			return fmt.Errorf(
				"identifiant invalide %q : lettres, chiffres, point, tiret, souligné et arobase uniquement (128 caractères max)",
				input)
		}
	}
	return nil
}

// callerName retourne le nom de la fonction appelante, pour les journaux.
//
// Niveau 2 : callerName elle-même, puis la fonction de filtrage, puis
// l'appelant réel — c'est lui qu'on veut voir dans le journal.
func callerName() string {
	pc, _, _, _ := runtime.Caller(2)
	return runtime.FuncForPC(pc).Name()
}
