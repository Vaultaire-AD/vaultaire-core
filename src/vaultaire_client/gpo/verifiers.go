package gpo

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Les vérificateurs d'état système.
//
// # Pourquoi ceux-là, et pas les trente-six
//
// Ces cinq modules sont ceux dont la dérive DONNE UN DROIT. Un service de
// sécurité arrêté, une règle de pare-feu disparue, un compte remis dans sudo,
// SELinux repassé en permissive, une expiration de mot de passe levée : dans
// chaque cas, l'état qui remplace la politique est plus permissif qu'elle.
//
// Les autres modules dérivent aussi, mais leur dérive coûte de la cohérence, pas
// de la sécurité — un fuseau horaire, un alias de shell, une limite de
// ressources. Ils suivront, un par un.
//
// **Une vérification approximative est pire qu'aucune** : elle déclare conforme
// ce qui ne l'est pas, et personne ne va plus regarder. C'est la raison de ne
// pas les écrire toutes d'affilée.

// Les types d'attente, nommés plutôt qu'écrits en littéral aux deux endroits qui
// les emploient — l'appliqueur qui déclare, le registre qui vérifie.
const (
	CheckSystemdUnit = "systemd_unit"
	CheckNftRule     = "nft_rule"
	CheckGroupMember = "group_member"
	CheckSELinux     = "selinux"
	CheckAccountLock = "account_lock"
)

func init() {
	registerChecker(CheckSystemdUnit, verifierUniteSystemd)
	registerChecker(CheckNftRule, verifierRegleNft)
	registerChecker(CheckGroupMember, verifierAppartenance)
	registerChecker(CheckSELinux, verifierSELinux)
	registerChecker(CheckAccountLock, verifierVerrouillageCompte)
}

// --- unité systemd ----------------------------------------------------------

// verifierUniteSystemd constate l'état d'activation et d'exécution d'une unité.
//
// Expect porte les seules facettes que le module a réellement fixées :
// « enabled=enabled », « active=started », ou les deux. Une facette que la
// politique ne mentionne pas n'est pas vérifiée — l'administrateur local reste
// libre de démarrer un service que la GPO se contente d'activer au démarrage.
//
// # is-enabled et is-active rendent un code de sortie non nul
//
// `systemctl is-enabled` sort en erreur quand l'unité est désactivée, et
// `is-active` quand elle est arrêtée. La sortie TEXTE reste exploitable dans les
// deux cas — c'est elle qui fait foi ici, pas le code de retour. Traiter
// l'erreur comme « je n'ai pas pu savoir » rendrait le vérificateur aveugle
// précisément au cas qu'il cherche.
func verifierUniteSystemd(c SystemCheck) (bool, string, error) {
	if !commandExists("systemctl") {
		return false, "", fmt.Errorf("systemctl absent de cette machine")
	}
	attendu := champsAttendus(c.Expect)
	var ecarts []string

	if veut, ok := attendu["enabled"]; ok {
		sortie, _ := runCommand("systemctl", "is-enabled", c.Target)
		constate := strings.TrimSpace(sortie)
		if constate == "" {
			return false, "", fmt.Errorf("systemctl is-enabled %s sans reponse", c.Target)
		}
		// « enabled-runtime », « indirect », « alias » comptent comme activé :
		// l'unité démarrera au boot, ce que la politique demande. Les distinguer
		// ferait signaler une dérive sur des machines parfaitement conformes.
		actif := strings.HasPrefix(constate, "enabled") ||
			constate == "indirect" || constate == "alias" || constate == "static"
		if (veut == "enabled") != actif {
			ecarts = append(ecarts, ecartConstate("activation au demarrage", veut, constate))
		}
	}

	if veut, ok := attendu["active"]; ok {
		sortie, _ := runCommand("systemctl", "is-active", c.Target)
		constate := strings.TrimSpace(sortie)
		if constate == "" {
			return false, "", fmt.Errorf("systemctl is-active %s sans reponse", c.Target)
		}
		enMarche := constate == "active" || constate == "activating"
		if (veut == "started") != enMarche {
			ecarts = append(ecarts, ecartConstate("etat", veut, constate))
		}
	}

	if len(ecarts) == 0 {
		return true, "", nil
	}
	return false, c.Target + " : " + strings.Join(ecarts, " ; "), nil
}

// --- règle nftables ---------------------------------------------------------

// verifierRegleNft constate la présence d'une règle dans la table Vaultaire.
//
// La règle est retrouvée par son COMMENTAIRE, comme à la suppression : c'est le
// seul lien stable entre un module de GPO et la règle qu'il a posée. Voir
// cleRegleNft.
//
// # Le défaut que cela ferme
//
// La version antérieure de la suppression vidait la chaîne entière. Les autres
// règles disparaissaient, et rien ne le signalait — le scan ne couvrait que les
// fichiers. La machine était déclarée conforme, pare-feu grand ouvert. La
// suppression a été corrigée (point 15), mais le point aveugle demeurait : un
// `nft flush ruleset` local produisait exactement le même silence.
func verifierRegleNft(c SystemCheck) (bool, string, error) {
	if !commandExists("nft") {
		// Le pare-feu peut être firewalld : l'attente n'a alors pas de sens sur
		// cette machine. On ne peut rien constater, on le dit.
		return false, "", fmt.Errorf("nft absent de cette machine")
	}

	sortie, err := runCommand("nft", "-j", "list", "chain", "inet", vaultaireNftTable, "input")
	if err != nil {
		// La table n'existe pas : aucune règle Vaultaire n'est en place. C'est un
		// CONSTAT, pas une incertitude — et si la politique attendait une règle,
		// c'est bien une dérive.
		if c.Expect == "absent" {
			return true, "", nil
		}
		return false, "la table " + vaultaireNftTable + " n'existe plus : aucune regle Vaultaire en place", nil
	}

	var doc struct {
		Nftables []regleNft `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(sortie), &doc); err != nil {
		return false, "", fmt.Errorf("sortie JSON de nft illisible : %v", err)
	}

	present := false
	for _, r := range doc.Nftables {
		if r.Rule.Comment == c.Target {
			present = true
			break
		}
	}

	veutPresente := c.Expect != "absent"
	if present == veutPresente {
		return true, "", nil
	}
	if veutPresente {
		return false, "regle de pare-feu " + c.Target + " disparue", nil
	}
	return false, "regle de pare-feu " + c.Target + " reapparue alors que la politique la retire", nil
}

// --- appartenance de groupe -------------------------------------------------

// verifierAppartenance constate qu'un compte est, ou n'est pas, dans un groupe.
//
// Target est « utilisateur:groupe ».
//
// # Pourquoi user.LookupGroupId et pas /etc/group
//
// Les groupes peuvent venir de NSS — LDAP, ou le module Vaultaire lui-même. Lire
// /etc/group directement verrait une machine conforme comme dérivée dès que le
// groupe est fourni par l'annuaire.
func verifierAppartenance(c SystemCheck) (bool, string, error) {
	compte, groupe, ok := strings.Cut(c.Target, ":")
	if !ok || compte == "" || groupe == "" {
		return false, "", fmt.Errorf("cible %q malformee (attendu utilisateur:groupe)", c.Target)
	}

	u, err := user.Lookup(compte)
	if err != nil {
		// Compte disparu. Ce n'est pas une incertitude : il n'est plus membre de
		// rien. Mais ce n'est pas non plus l'objet de ce module, et le signaler
		// comme un écart d'appartenance embrouillerait le diagnostic.
		return false, "", fmt.Errorf("compte %s inconnu localement", compte)
	}
	g, err := user.LookupGroup(groupe)
	if err != nil {
		if c.Expect == "absent" {
			return true, "", nil
		}
		return false, "groupe " + groupe + " disparu de la machine", nil
	}

	ids, err := u.GroupIds()
	if err != nil {
		return false, "", fmt.Errorf("groupes de %s illisibles : %v", compte, err)
	}
	membre := false
	for _, id := range ids {
		if id == g.Gid {
			membre = true
			break
		}
	}

	veutMembre := c.Expect != "absent"
	if membre == veutMembre {
		return true, "", nil
	}
	if veutMembre {
		return false, compte + " n'est plus membre de " + groupe, nil
	}
	// Le cas qui compte : un compte remis dans sudo ou wheel après qu'une
	// politique l'en a retiré.
	return false, compte + " est de nouveau membre de " + groupe +
		" alors que la politique l'en retire", nil
}

// --- SELinux ----------------------------------------------------------------

// verifierSELinux constate le mode courant ou la valeur d'un booléen.
//
// Target vaut « mode », ou « bool:<nom> ».
//
// # Le mode COURANT, pas le mode persistant
//
// L'appliqueur écrit les deux — setenforce pour maintenant, /etc/selinux/config
// pour le prochain démarrage. Le fichier est déjà surveillé par le scan des
// fichiers ; c'est donc le mode courant qu'il reste à constater, et c'est celui
// qui protège la machine en ce moment.
func verifierSELinux(c SystemCheck) (bool, string, error) {
	if nom, ok := strings.CutPrefix(c.Target, "bool:"); ok {
		if !commandExists("getsebool") {
			return false, "", fmt.Errorf("getsebool absent de cette machine")
		}
		sortie, err := runCommand("getsebool", nom)
		if err != nil {
			return false, "", fmt.Errorf("getsebool %s : %v", nom, err)
		}
		// Sortie de la forme « nom --> on ».
		_, valeur, ok := strings.Cut(sortie, "-->")
		if !ok {
			return false, "", fmt.Errorf("sortie de getsebool %s illisible", nom)
		}
		constate := strings.TrimSpace(valeur)
		if constate == strings.TrimSpace(c.Expect) {
			return true, "", nil
		}
		return false, ecartConstate("booleen SELinux "+nom, c.Expect, constate), nil
	}

	if !commandExists("getenforce") {
		return false, "", fmt.Errorf("getenforce absent de cette machine")
	}
	sortie, err := runCommand("getenforce")
	if err != nil {
		return false, "", fmt.Errorf("getenforce : %v", err)
	}
	constate := strings.ToLower(strings.TrimSpace(sortie))
	if constate == strings.ToLower(strings.TrimSpace(c.Expect)) {
		return true, "", nil
	}
	// « disabled » mérite d'être distingué : SELinux n'a pas été assoupli, il a
	// été coupé au démarrage, et aucun setenforce ne le rallumera.
	if constate == "disabled" {
		return false, "SELinux est desactive au niveau du noyau (mode " + c.Expect +
			" attendu) — un redemarrage est necessaire pour le retablir", nil
	}
	return false, ecartConstate("mode SELinux", c.Expect, constate), nil
}

// --- verrouillage et vieillissement d'un compte local -----------------------

// verifierVerrouillageCompte constate l'état d'un compte local non-Vaultaire.
//
// Expect porte les facettes fixées par la politique : « locked=yes »,
// « max=90 », « inactive=30 ».
//
// # Pourquoi /etc/shadow pour le verrou et chage pour le reste
//
// Un mot de passe verrouillé se lit à son empreinte préfixée par « ! » dans
// /etc/shadow. `passwd -S` le dirait aussi, mais sa sortie diffère d'une
// distribution à l'autre — « L », « LK », « locked » — et s'appuyer dessus
// ferait un vérificateur juste sur la machine de développement et faux ailleurs.
//
// Le vieillissement, lui, n'est pas lisible sans interpréter les colonnes de
// /etc/shadow en jours depuis l'époque. `chage -l` fait ce calcul, et sa sortie
// est stable là-dessus.
func verifierVerrouillageCompte(c SystemCheck) (bool, string, error) {
	attendu := champsAttendus(c.Expect)
	var ecarts []string

	if veut, ok := attendu["locked"]; ok {
		verrouille, err := motDePasseVerrouille(c.Target)
		if err != nil {
			return false, "", err
		}
		if (veut == "yes") != verrouille {
			etat := "deverrouille"
			if verrouille {
				etat = "verrouille"
			}
			ecarts = append(ecarts, ecartConstate("mot de passe", veut, etat))
		}
	}

	besoinChage := false
	for _, cle := range []string{"max", "inactive"} {
		if _, ok := attendu[cle]; ok {
			besoinChage = true
		}
	}
	if besoinChage {
		if !commandExists("chage") {
			return false, "", fmt.Errorf("chage absent de cette machine")
		}
		sortie, err := runCommand("chage", "-l", c.Target)
		if err != nil {
			return false, "", fmt.Errorf("chage -l %s : %v", c.Target, err)
		}
		valeurs := lireChage(sortie)

		if veut, ok := attendu["max"]; ok {
			if constate, connu := valeurs["max"]; !connu || constate != veut {
				ecarts = append(ecarts, ecartConstate("age maximal", veut, ouInconnu(constate, connu)))
			}
		}
		if veut, ok := attendu["inactive"]; ok {
			if constate, connu := valeurs["inactive"]; !connu || constate != veut {
				ecarts = append(ecarts, ecartConstate("inactivite", veut, ouInconnu(constate, connu)))
			}
		}
	}

	if len(ecarts) == 0 {
		return true, "", nil
	}
	return false, c.Target + " : " + strings.Join(ecarts, " ; "), nil
}

// motDePasseVerrouille lit /etc/shadow.
//
// Un mot de passe verrouillé porte un « ! » ou un « * » en tête d'empreinte.
// Les deux comptent : usermod -L pose « ! », et certains outils « * ».
func motDePasseVerrouille(compte string) (bool, error) {
	contenu, err := os.ReadFile(shadowPath())
	if err != nil {
		return false, fmt.Errorf("lecture de %s : %v", shadowPath(), err)
	}
	for _, ligne := range strings.Split(string(contenu), "\n") {
		if !strings.HasPrefix(ligne, compte+":") {
			continue
		}
		champs := strings.Split(ligne, ":")
		if len(champs) < 2 {
			return false, fmt.Errorf("ligne de %s malformee dans shadow", compte)
		}
		h := champs[1]
		return strings.HasPrefix(h, "!") || strings.HasPrefix(h, "*"), nil
	}
	return false, fmt.Errorf("compte %s absent de shadow", compte)
}

// lireChage extrait l'âge maximal et l'inactivité de la sortie de `chage -l`.
//
// La sortie est localisée : « Maximum number of days » en anglais, « Nombre
// maximal de jours » en français. Les libellés ne sont donc PAS un repère
// fiable — c'est la valeur après le « : » qui l'est, et l'ORDRE des lignes, que
// chage ne change pas.
//
// Repérage par mot-clé quand il est reconnu, et rien sinon : une valeur qu'on
// ne sait pas lire vaut « inconnue », ce qui produit un écart explicite plutôt
// qu'une conformité inventée.
func lireChage(sortie string) map[string]string {
	out := map[string]string{}
	for _, ligne := range strings.Split(sortie, "\n") {
		bas := strings.ToLower(ligne)
		_, valeur, ok := strings.Cut(ligne, ":")
		if !ok {
			continue
		}
		valeur = strings.TrimSpace(valeur)
		switch {
		case strings.Contains(bas, "maximum") || strings.Contains(bas, "maximal"):
			if _, err := strconv.Atoi(valeur); err == nil {
				out["max"] = valeur
			}
		case strings.Contains(bas, "inactive") || strings.Contains(bas, "inactivit"):
			if _, err := strconv.Atoi(valeur); err == nil {
				out["inactive"] = valeur
			}
		}
	}
	return out
}

func ouInconnu(v string, connu bool) string {
	if !connu {
		return "inconnu"
	}
	return v
}

// shadowPath est indirect pour que les tests puissent le déplacer : /etc/shadow
// n'est lisible que par root, et un test qui l'exigerait ne serait jamais lancé.
var fichierShadow = "/etc/shadow"

func shadowPath() string { return fichierShadow }
