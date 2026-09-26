package passwordpolicy

import (
	"database/sql"
	"fmt"
	"strings"
	"unicode"

	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/global/security"
	"vaultaire/core/logs"
)

// La robustesse des mots de passe de l'annuaire — TO-DO 100.
//
// # Ce qui manquait
//
// Ce paquet ne portait QUE l'expiration. Aucune longueur minimale, aucun
// interdit, nulle part : le portail acceptait n'importe quelle chaîne non vide,
// « 1234 » compris, et la ligne de commande aussi.
//
// argon2id (19 Mio, 2 passes) protège d'une attaque HORS LIGNE, sur une base
// volée. Il ne fait rien contre une attaque EN LIGNE, et le freinage du produit
// ne verrouille jamais : trois essais gratuits, puis un refus plafonné à trente
// secondes, oublié au bout de quinze minutes — soit environ deux essais par
// minute, indéfiniment. Les dix mots de passe les plus courants tombent en une
// soirée. Tout le soin mis dans le hachage ne sert à rien si le secret fait
// quatre chiffres.
//
// # La longueur, et presque rien d'autre
//
// Pas de règle de complexité — majuscule, chiffre, caractère spécial. Elle
// produit « Password1! », qui est dans toutes les listes, et pousse à écrire le
// mot de passe sur un papier. C'est la longueur qui coûte à l'attaquant, et
// c'est la recommandation de l'ANSSI comme du NIST.
//
// S'y ajoute une seule famille d'interdits : ce qu'un attaquant essaie EN
// PREMIER parce qu'il connaît déjà sa cible — le nom du compte, le domaine, le
// nom du produit — et la poignée de classiques universels. Une liste de dix
// mille mots courants aurait été du théâtre : elle se contourne en ajoutant un
// chiffre, et elle refuse des mots de passe longs et bons parce qu'ils
// contiennent « soleil ».
//
// # Ce que la règle ne fait PAS
//
// Elle ne s'applique jamais à un mot de passe déjà en base. On ne peut pas
// recalculer ce qu'on refuserait : le mot de passe n'existe nulle part. Le parc
// s'y conforme à la première écriture de chacun, exactement comme pour le
// passage à argon2id.

// Exigences est la règle appliquée à un mot de passe neuf.
//
// Une structure et non les réglages bruts : la règle est éprouvée sans base, et
// la faire dépendre de `dbauthpolicy` obligerait chaque test à en fabriquer un.
type Exigences struct {
	// LongueurMin est comptée en RUNES et non en octets — voir Controler.
	LongueurMin int

	// Interdits sont les fragments qui ne doivent pas apparaître dans le mot de
	// passe, comparés sans tenir compte de la casse ni des accents.
	Interdits []string
}

// classiques sont les mots de passe qu'un attaquant essaie avant tout le reste.
//
// Volontairement COURTE. Son rôle n'est pas de couvrir les dictionnaires — le
// freinage et la longueur s'en chargent — mais de refuser ce qui serait
// autrement accepté par une règle de longueur seule, parce que la chaîne est
// assez longue : « motdepasse123 » fait treize caractères.
var classiques = []string{
	"password", "passwd", "motdepasse", "motpasse", "azerty", "qwerty",
	"administrateur", "administrator", "changeme", "changezmoi",
	"bienvenue", "welcome", "iloveyou", "letmein", "secret",
	"123456", "1234567", "12345678", "123456789", "1234567890",
	"abcdef", "abcdefg", "qwertyuiop", "azertyuiop",
}

// ExigencesPour compose la règle applicable à un compte.
//
// Le nom du compte et son domaine viennent de l'appelant parce qu'ils sont
// PROPRES À LA CIBLE : un interdit universel ne peut pas les contenir, et les
// oublier laisserait passer le mot de passe qu'un attaquant essaie en deuxième,
// juste après « password ».
func ExigencesPour(longueurMin int, username string) Exigences {
	interdits := append([]string(nil), classiques...)
	interdits = append(interdits, "vaultaire")

	// Le nom complet, sa partie locale et les libellés du domaine.
	//
	// « alice@paris.acme.fr » interdit « alice », « paris », « acme » — pas
	// « fr » : un fragment de deux lettres apparaît dans trop de mots de passe
	// honnêtes, et le refuser produirait un message incompréhensible.
	for _, morceau := range decouperIdentite(username) {
		if len([]rune(morceau)) >= 4 {
			interdits = append(interdits, morceau)
		}
	}
	return Exigences{LongueurMin: longueurMin, Interdits: interdits}
}

func decouperIdentite(username string) []string {
	u := strings.ToLower(strings.TrimSpace(username))
	if u == "" {
		return nil
	}
	morceaux := []string{u}
	local, domaine, coupe := strings.Cut(u, "@")
	if coupe {
		morceaux = append(morceaux, local)
		morceaux = append(morceaux, strings.Split(domaine, ".")...)
	}
	// « jean.dupont » donne aussi « jean » et « dupont » : le point sépare
	// autant un prénom d'un nom qu'un libellé de domaine d'un autre.
	morceaux = append(morceaux, strings.FieldsFunc(local, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})...)
	return morceaux
}

// Controler applique la règle et rend ce qui MANQUE.
//
// Fonction pure : ni base, ni horloge. Elle rend une liste plutôt qu'une erreur
// pour que l'appelant compose un message qui dit tout d'un coup — signaler un
// défaut à la fois fait retaper un mot de passe trois fois de suite.
//
// # Le message dit ce qui manque, pas « mot de passe invalide »
//
// Un refus qui ne dit rien se contourne en essayant des variantes au hasard,
// donc en finissant sur quelque chose d'à peine acceptable. Et il n'apprend
// rien à un attaquant : la règle est publique, elle est dans cette
// documentation.
func Controler(e Exigences, motDePasse string) []string {
	var manques []string

	// En RUNES et non en octets. « épée » fait quatre caractères et six
	// octets : compter en octets rendrait la règle plus laxiste pour qui écrit
	// en ASCII et plus stricte pour les autres, sans que rien ne le dise.
	longueur := len([]rune(motDePasse))
	if e.LongueurMin > 0 && longueur < e.LongueurMin {
		manques = append(manques, fmt.Sprintf(
			"il fait %d caractère(s), il en faut au moins %d", longueur, e.LongueurMin))
	}

	// Les espaces de tête et de queue sont refusés, mais pas ceux du milieu :
	// une phrase de passe est exactement ce qu'on veut encourager. Un espace en
	// bordure, lui, est presque toujours une coquille de copier-coller, et il
	// produit un mot de passe que l'utilisateur ne saura pas retaper.
	if motDePasse != strings.TrimSpace(motDePasse) {
		manques = append(manques, "il commence ou finit par une espace")
	}

	normalise := normaliser(motDePasse)
	for _, interdit := range e.Interdits {
		i := normaliser(interdit)
		if i != "" && strings.Contains(normalise, i) {
			manques = append(manques, fmt.Sprintf("il contient « %s », trop prévisible", interdit))
			// Un seul interdit signalé : les énumérer tous décrirait la liste à
			// qui la sonde, et la première occurrence suffit à corriger.
			break
		}
	}

	// Un mot de passe d'un seul caractère répété passe la longueur sans rien
	// valoir : « aaaaaaaaaaaa » fait douze caractères.
	if longueur > 0 && longueur >= e.LongueurMin && unCaractereRepete(motDePasse) {
		manques = append(manques, "il ne répète qu'un seul caractère")
	}

	return manques
}

// normaliser met en minuscules et retire ce qui sert à déguiser un mot.
//
// Les accents, les espaces et la substitution de chiffres aux lettres :
// « P@ssw0rd » et « password » sont le même mot de passe pour qui attaque, et
// une liste d'interdits qui ne les rapproche pas ne sert à rien.
func normaliser(s string) string {
	remplacements := map[rune]rune{
		'0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
		'@': 'a', '$': 's', '!': 'i', '€': 'e',
		'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
		'à': 'a', 'â': 'a', 'ä': 'a',
		'î': 'i', 'ï': 'i', 'ô': 'o', 'ö': 'o',
		'ù': 'u', 'û': 'u', 'ü': 'u', 'ç': 'c',
	}
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsSpace(r) {
			continue
		}
		if sub, ok := remplacements[r]; ok {
			b.WriteRune(sub)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func unCaractereRepete(s string) bool {
	runes := []rune(s)
	for _, r := range runes[1:] {
		if r != runes[0] {
			return false
		}
	}
	return true
}

// ErreurRobustesse porte un refus lisible par un humain.
type ErreurRobustesse struct {
	Manques []string
}

func (e *ErreurRobustesse) Error() string {
	if len(e.Manques) == 1 {
		return "mot de passe refusé : " + e.Manques[0]
	}
	return "mot de passe refusé : " + strings.Join(e.Manques, " ; ")
}

// PreparerNouveauMotDePasse contrôle la robustesse PUIS hache.
//
// # C'est le point d'écriture unique du point 100
//
// La règle ne vit dans aucune façade. Le portail, `vlt`, la réinitialisation
// par un administrateur et l'amorçage passent tous par ici, parce qu'ils ont
// tous besoin de la même chose : transformer un mot de passe en clair en
// empreinte destinée à la base. Brancher le contrôle sur ce besoin plutôt que
// sur chaque appelant est ce qui garantit qu'une cinquième façade, écrite plus
// tard, sera couverte sans que personne n'y pense — c'est exactement l'erreur
// que ce point corrige.
//
// Un test-sentinelle (robustesse_test.go) refuse que `security.Hacher` soit
// appelée ailleurs, à une exception près : le réencodage à la connexion, qui
// remplace une empreinte par une autre SANS que l'utilisateur ait choisi un
// nouveau mot de passe. Le contrôler là refuserait la connexion d'un compte
// dont le mot de passe était acceptable le jour où il l'a choisi.
//
// # Pourquoi la base est un paramètre et pas une variable globale
//
// L'amorçage appelle cette fonction AVANT qu'aucun service n'écoute, et les
// tests l'appellent sans base du tout. Une base nulle fait retomber sur la
// politique par défaut, qui porte le plancher : sans base, on durcit.
func PreparerNouveauMotDePasse(db *sql.DB, username, motDePasse string) (empreinte, selHex string, err error) {
	politique := dbauthpolicy.GetPasswordPolicy(db)

	exigences := ExigencesPour(politique.MinLength, username)
	if manques := Controler(exigences, motDePasse); len(manques) > 0 {
		// Le mot de passe refusé n'apparaît NULLE PART, ni ici ni dans le
		// journal : c'est la règle déjà tenue partout ailleurs, et un mot de
		// passe refusé est souvent une variante d'un mot de passe valide.
		logs.Write_Log("INFO", fmt.Sprintf(
			"authpolicy: mot de passe refusé pour %s (%d critère(s) non tenu(s))",
			username, len(manques)))
		return "", "", &ErreurRobustesse{Manques: manques}
	}

	return security.Hacher(motDePasse)
}
