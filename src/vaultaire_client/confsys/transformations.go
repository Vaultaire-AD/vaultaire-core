package confsys

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Les transformations : ce que l'agent écrit, à partir de ce qui est en place.
// Chacune reprend l'étape du script d'installation qui écrit le même fichier,
// règle pour règle — y compris ses étrangetés : la réconciliation ne doit rien
// produire que l'installation n'aurait pas produit.

// PrefixeMarqueur : toute ligne qui commence ainsi est un marqueur de
// Vaultaire, retiré avant d'écrire le marqueur à jour.
const PrefixeMarqueur = "# vaultaire-conf"

var reVersion = regexp.MustCompile(`(?m)^# vaultaire-conf v([0-9]{1,6})\b`)

// LireVersion rend la version du premier marqueur du fichier, 0 sans marqueur
// — un fichier écrit avant le 117, ou jamais par Vaultaire.
func LireVersion(contenu string) int {
	m := reVersion.FindStringSubmatch(contenu)
	if m == nil {
		return 0
	}
	v, _ := strconv.Atoi(m[1])
	return v
}

// lignes découpe un fichier texte ; une dernière ligne sans saut de ligne
// compte comme une ligne (awk et sed font de même).
func lignes(contenu string) []string {
	if contenu == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(contenu, "\n"), "\n")
}

func joindre(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return strings.Join(l, "\n") + "\n"
}

var (
	// Les deux motifs de l'awk de debian.sh.
	reLigneVaultaire = regexp.MustCompile(`# vaultaire[ \t]*$`)
	reCommonAuth     = regexp.MustCompile(`^[ \t]*@include[ \t]+common-auth([ \t]|$)`)
	reCommonSession  = regexp.MustCompile(`^[ \t]*@include[ \t]+common-session([ \t]|$)`)
)

// ErrPileNonBranchable : une pile Debian sans « @include common-auth » — elle
// a été personnalisée, et ni le script ni l'agent ne devinent où s'y brancher.
var ErrPileNonBranchable = fmt.Errorf("« @include common-auth » absent : pile personnalisée, branchement à faire à la main")

// brancherPileDebian : l'awk de debian.sh, preparer_pile, en Go.
//
// Retire les lignes de Vaultaire (« # vaultaire » en fin de ligne) et les
// marqueurs ; pose le marqueur en tête (après « #%PAM » s'il ouvre le
// fichier) ; la ligne d'authentification juste avant le premier
// « @include common-auth » ; la ligne de session juste après le premier
// « @include common-session », ou en fin de fichier.
func brancherPileDebian(contenu, auth, session string) (string, error) {
	var out []string
	marque, a, s := false, false, false
	for i, l := range lignes(contenu) {
		if reLigneVaultaire.MatchString(l) || strings.HasPrefix(l, PrefixeMarqueur) {
			continue
		}
		if i == 0 && strings.HasPrefix(l, "#%PAM") {
			out = append(out, l, MarquePAM)
			marque = true
			continue
		}
		if !marque {
			out = append(out, MarquePAM)
			marque = true
		}
		if !a && reCommonAuth.MatchString(l) {
			out = append(out, auth+"  # vaultaire")
			a = true
		}
		out = append(out, l)
		if session != "" && !s && reCommonSession.MatchString(l) {
			out = append(out, session+"  # vaultaire")
			s = true
		}
	}
	if !a {
		return "", ErrPileNonBranchable
	}
	if session != "" && !s {
		out = append(out, session+"  # vaultaire")
	}
	return joindre(out), nil
}

// reecrireSSHD : l'étape 7 des deux scripts. Retire les marqueurs et toute
// ligne qui commence par une directive tenue (y compris « Include » : le bloc
// remet la sienne APRÈS ses directives, pour qu'elles l'emportent sur
// sshd_config.d — la première valeur lue gagne), puis pose le bloc AVANT le
// premier « Match », ou en fin de fichier (TO-DO 208) : après un Match, il y
// serait enfermé, et sshd -t le refuserait.
//
// sshd_config.d/*.conf n'est PAS touché : l'installation y a neutralisé
// PasswordAuthentication et KbdInteractiveAuthentication une fois, et les
// directives du bloc, lues avant l'Include, l'emportent de toute façon.
func reecrireSSHD(contenu string) string {
	var out []string
	for _, l := range lignes(contenu) {
		if strings.HasPrefix(l, PrefixeMarqueur) {
			continue
		}
		tenue := false
		for _, d := range directivesSSHD {
			if strings.HasPrefix(l, d) {
				tenue = true
				break
			}
		}
		if !tenue {
			out = append(out, l)
		}
	}
	for i, l := range out {
		if reMatch.MatchString(l) {
			return joindre(out[:i]) + blocSSHD + joindre(out[i:])
		}
	}
	return joindre(out) + blocSSHD
}

// reMatch : l'awk des scripts, « tolower($0) ~ /^[[:space:]]*match[[:space:]]/ ».
var reMatch = regexp.MustCompile(`^[[:space:]]*(?i:match)[[:space:]]`)

// ErrNSSIncomplet : nsswitch.conf sans ligne passwd: ou group: — le script
// n'y ajoutait rien, en silence ; l'agent le dit.
var ErrNSSIncomplet = fmt.Errorf("nsswitch.conf sans ligne « passwd: » ou « group: »")

// brancherNSS : l'étape 6 des deux scripts — « vaultaire » ajouté en fin des
// lignes passwd: et group: qui ne le nomment pas — puis le marqueur en tête.
func brancherNSS(contenu string) (string, error) {
	l := lignes(contenu)
	for _, db := range []string{"passwd", "group"} {
		deja := regexp.MustCompile(`^` + db + `:.*\bvaultaire\b`)
		present, branche := false, false
		for _, x := range l {
			if strings.HasPrefix(x, db+":") {
				present = true
			}
			if deja.MatchString(x) {
				branche = true
			}
		}
		if !present {
			return "", ErrNSSIncomplet
		}
		if branche {
			continue
		}
		for i, x := range l {
			if strings.HasPrefix(x, db+":") {
				l[i] = x + " vaultaire"
			}
		}
	}
	out := []string{MarquePAM}
	for _, x := range l {
		if !strings.HasPrefix(x, PrefixeMarqueur) {
			out = append(out, x)
		}
	}
	return joindre(out), nil
}
