package gpo

import (
	"fmt"
	"strings"
)

// Les vérificateurs des modules de COHÉRENCE.
//
// # Ce qui les sépare des cinq premiers
//
// Les cinq vérificateurs de verifiers.go couvrent les modules dont la dérive
// DONNE UN DROIT : un service arrêté, une règle de pare-feu disparue, un compte
// remis dans sudo. Ceux-ci couvrent des modules dont la dérive coûte de la
// cohérence — une valeur de noyau revenue à son défaut, un paquet désinstallé à
// la main, un shell changé. La machine reste sûre ; elle n'est simplement plus
// celle que la politique décrit.
//
// La règle d'écriture est la même, et c'est la seule qui compte ici :
//
//	Une vérification approximative est PIRE qu'aucune.
//
// Elle déclare conforme ce qui ne l'est pas, et personne ne va plus regarder.
// D'où trois refus assumés dans ce fichier — la version d'un paquet, une ACL
// récursive, et tout ce qui dépend d'un redémarrage — chacun documenté à
// l'endroit où l'on aurait pu faire semblant.

const (
	// CheckSysctl : Target est la clé, Expect la valeur attendue.
	CheckSysctl = "sysctl"
	// CheckPackage : Target est le nom du paquet, Expect « present » ou « absent ».
	CheckPackage = "package"
	// CheckUserShell : Target est le compte, Expect le chemin du shell.
	CheckUserShell = "user_shell"
	// CheckFileACL : Target est « <chemin>|<u|g>:<beneficiaire> », Expect les
	// droits attendus ou « absent ».
	CheckFileACL = "file_acl"
)

func init() {
	registerChecker(CheckSysctl, verifierSysctl)
	registerChecker(CheckPackage, verifierPaquet)
	registerChecker(CheckUserShell, verifierShell)
	registerChecker(CheckFileACL, verifierACL)
}

// --- sysctl -----------------------------------------------------------------

// verifierSysctl constate la valeur COURANTE d'une clé du noyau.
//
// # Pourquoi ce vérificateur ajoute quelque chose
//
// Le fichier /etc/sysctl.d/90-vaultaire-*.conf est déjà surveillé par le scan
// des fichiers. Mais il ne décrit que ce qui sera appliqué au PROCHAIN
// démarrage : un `sysctl -w net.ipv4.ip_forward=1` passé à la main change la
// valeur en vigueur sans toucher au fichier. Le scan voyait un fichier intact
// et déclarait la machine conforme, noyau reconfiguré.
//
// # La normalisation des espaces n'est pas cosmétique
//
// Plusieurs clés portent plusieurs valeurs, séparées par des TABULATIONS dans la
// sortie de sysctl et le plus souvent par des espaces dans la politique :
//
//	net.ipv4.ip_local_port_range = 32768	60999
//
// Comparer les chaînes telles quelles ferait signaler une dérive permanente sur
// une machine parfaitement conforme — et une dérive permanente qu'aucune
// réapplication ne corrige est le plus sûr moyen de faire cesser de lire les
// rapports.
func verifierSysctl(c SystemCheck) (bool, string, error) {
	if !commandExists("sysctl") {
		return false, "", fmt.Errorf("sysctl absent de cette machine")
	}

	sortie, err := runCommand("sysctl", "-n", c.Target)
	if err != nil {
		// La clé n'existe plus dans le noyau courant : module déchargé, espace de
		// noms restreint en conteneur, noyau différent depuis le dernier
		// démarrage.
		//
		// Incertitude et NON écart, délibérément. Un écart déclencherait une
		// réapplication, et l'appliqueur échouerait exactement de la même façon —
		// à chaque cycle, indéfiniment. Dire « je n'ai pas pu savoir » place le
		// problème là où un administrateur peut le traiter.
		return false, "", fmt.Errorf("valeur de %s illisible : %v", c.Target, err)
	}

	constate := normaliserEspaces(sortie)
	attendu := normaliserEspaces(c.Expect)
	if constate == attendu {
		return true, "", nil
	}
	return false, ecartConstate("sysctl "+c.Target, attendu, constate), nil
}

// normaliserEspaces réduit toute suite d'espaces et de tabulations à un espace.
func normaliserEspaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// --- paquet -----------------------------------------------------------------

// verifierPaquet constate la présence ou l'absence d'un paquet.
//
// # La VERSION n'est pas vérifiée, et c'est un choix
//
// La politique peut épingler une version. La constater supposerait de comparer
// des chaînes que chaque gestionnaire écrit à sa façon : rpm préfixe d'une
// époque (« 1:2.4.6 ») quand elle n'est pas nulle et suffixe d'une révision
// (« -3.el9 »), dpkg garde l'époque mais pas la même révision, et la politique
// porte le plus souvent la version amont seule.
//
// Un comparateur qui se tromperait signalerait une dérive sur une machine
// conforme, ou — bien pire — déclarerait conforme une version qui ne l'est pas.
// Ce vérificateur affirme donc UNIQUEMENT ce qu'il constate : le paquet est là,
// ou il n'y est pas. L'épinglage de version reste porté par le fichier de
// politique et par l'appliqueur, qui échouerait s'il ne pouvait pas l'obtenir.
func verifierPaquet(c SystemCheck) (bool, string, error) {
	installe, err := paquetInstalle(c.Target)
	if err != nil {
		return false, "", err
	}

	veutInstalle := c.Expect != "absent"
	if installe == veutInstalle {
		return true, "", nil
	}
	if veutInstalle {
		return false, "paquet " + c.Target + " desinstalle", nil
	}
	return false, "paquet " + c.Target + " reinstalle alors que la politique le retire", nil
}

// paquetInstalle interroge le gestionnaire de paquets de la machine.
//
// # Pourquoi dpkg-query et non « dpkg -s »
//
// Les deux disent la même chose, mais dpkg-query rend un format CHOISI par
// l'appelant. `dpkg -s` rend un bloc de champs dont l'ordre et la traduction
// dépendent de la locale ; en extraire un statut demanderait exactement le genre
// d'analyse fragile que ce fichier cherche à éviter.
//
// # « deinstall ok config-files » compte comme ABSENT
//
// Un paquet retiré sans purge laisse ses fichiers de configuration et garde une
// entrée dans la base dpkg. Le compter comme présent — c'est ce que fait un test
// sur le seul code de retour — déclarerait conforme une machine dont le logiciel
// a été désinstallé.
func paquetInstalle(pkg string) (bool, error) {
	switch {
	case commandExists("dpkg-query"):
		// Le code de retour d'abord, la sortie ensuite — et surtout PAS le texte
		// du message. `dpkg-query -W` sur un paquet inconnu de la base sort en
		// erreur avec « no packages found matching … », traduit dans la langue de
		// la machine. Reconnaître ce message imposerait de tenir la liste de ses
		// traductions, et un agent installé sur une machine allemande cesserait
		// silencieusement de constater quoi que ce soit.
		//
		// L'interrogation porte sur UN paquet nommé : un échec signifie que dpkg
		// ne le connaît pas, c'est-à-dire qu'il n'est pas installé.
		sortie, err := runCommand("dpkg-query", "-W", "-f", "${db:Status-Status}", pkg)
		if err != nil {
			return false, nil
		}
		return strings.TrimSpace(sortie) == "installed", nil

	case commandExists("rpm"):
		// -q sort en erreur quand le paquet n'est pas installé, avec un message
		// sur la sortie standard. Le code de retour suffit ici : rpm ne connaît
		// pas d'état intermédiaire équivalent à « config-files ».
		if _, err := runCommand("rpm", "-q", pkg); err != nil {
			return false, nil
		}
		return true, nil
	}
	return false, fmt.Errorf("ni dpkg-query ni rpm sur cette machine : etat des paquets inverifiable")
}

// --- shell de connexion -----------------------------------------------------

// verifierShell constate le shell de connexion d'un compte.
//
// # getent et non /etc/passwd
//
// Même raison que pour l'appartenance de groupe : les comptes peuvent venir de
// NSS — LDAP, ou le module Vaultaire lui-même. Lire /etc/passwd directement
// verrait « compte inconnu » sur une machine où le compte existe parfaitement,
// et l'agent signalerait une dérive sur tout un parc d'utilisateurs de domaine.
//
// os/user ne sert pas ici : sa structure User ne porte pas le shell.
func verifierShell(c SystemCheck) (bool, string, error) {
	if !commandExists("getent") {
		return false, "", fmt.Errorf("getent absent de cette machine")
	}
	sortie, err := runCommand("getent", "passwd", c.Target)
	if err != nil {
		return false, "", fmt.Errorf("compte %s inconnu de NSS", c.Target)
	}

	shell, err := shellDeLignePasswd(sortie)
	if err != nil {
		return false, "", err
	}
	if shell == strings.TrimSpace(c.Expect) {
		return true, "", nil
	}
	return false, ecartConstate("shell de "+c.Target, c.Expect, shell), nil
}

// shellDeLigneUtilisateur extrait le septième champ d'une ligne passwd.
//
// Le format est fixé par POSIX et ne varie pas d'une distribution à l'autre :
//
//	nom:mot_de_passe:uid:gid:gecos:home:shell
//
// Le champ GECOS peut contenir des virgules, jamais de deux-points — c'est
// précisément ce qui rend le découpage sûr.
func shellDeLigneUtilisateur(ligne string) (string, error) {
	champs := strings.Split(strings.TrimRight(ligne, "\n"), ":")
	if len(champs) < 7 {
		return "", fmt.Errorf("ligne passwd malformee (%d champs, 7 attendus)", len(champs))
	}
	return strings.TrimSpace(champs[6]), nil
}

// shellDeLignePasswd retient la PREMIÈRE ligne de la sortie de getent.
//
// Un compte peut apparaître deux fois — une entrée locale et une entrée
// d'annuaire portant le même nom. NSS résout dans l'ordre déclaré par
// nsswitch.conf, et c'est la première entrée qui fait foi pour l'ouverture de
// session : c'est donc elle qu'il faut constater, pas la dernière.
func shellDeLignePasswd(sortie string) (string, error) {
	for _, ligne := range strings.Split(sortie, "\n") {
		if strings.TrimSpace(ligne) == "" {
			continue
		}
		return shellDeLigneUtilisateur(ligne)
	}
	return "", fmt.Errorf("getent passwd sans reponse exploitable")
}

// --- ACL POSIX --------------------------------------------------------------

// verifierACL constate une entrée d'ACL sur un chemin.
//
// Target est « <chemin>|<u|g>:<beneficiaire> », Expect les droits attendus
// (« rwx », « r-x », « --- ») ou « absent ».
//
// # Les ACL récursives ne sont PAS vérifiées
//
// Une politique récursive pose l'entrée sur toute une arborescence. Ce
// vérificateur ne constate que le chemin de tête : une ACL retirée sur un
// sous-répertoire lui échapperait, et il déclarerait pourtant « conforme ».
//
// Plutôt que d'affirmer plus que ce qu'on constate, l'appliqueur ne déclare
// AUCUNE attente quand la politique est récursive — voir applyFileACL. Le silence
// est un défaut de couverture, connu et documenté ; la fausse conformité est un
// défaut de confiance, et il contamine tout le reste du rapport.
//
// # Les droits EFFECTIFS comptent, pas seulement l'entrée
//
// Le masque d'un ACL réduit les droits de toutes les entrées nommées. Une entrée
// « alice:rw- » sous un masque « r-- » donne à alice un accès en lecture seule,
// et getfacl l'annote « #effective:r-- ». Ne lire que l'entrée déclarerait
// conforme une politique que le masque annule.
func verifierACL(c SystemCheck) (bool, string, error) {
	chemin, spec, ok := decouperCibleACL(c.Target)
	if !ok {
		return false, "", fmt.Errorf("cible %q malformee (attendu <chemin>|<u|g>:<beneficiaire>)", c.Target)
	}
	if !commandExists("getfacl") {
		return false, "", fmt.Errorf("getfacl absent : etat des ACL inverifiable")
	}

	// --absolute-names : sans elle, getfacl retire le « / » de tête et les
	// messages d'erreur désignent un chemin relatif qui n'existe nulle part.
	// -c : pas d'en-tête de commentaires, que les entrées.
	sortie, err := runCommand("getfacl", "--absolute-names", "-c", chemin)
	if err != nil {
		return false, "", fmt.Errorf("ACL de %s illisibles : %v", chemin, err)
	}

	droits, effectifs, present := entreeACL(sortie, spec)
	veutPresente := strings.TrimSpace(c.Expect) != "absent"

	if !present {
		if !veutPresente {
			return true, "", nil
		}
		return false, "entree ACL " + spec + " disparue de " + chemin, nil
	}
	if !veutPresente {
		return false, "entree ACL " + spec + " reapparue sur " + chemin +
			" alors que la politique la retire", nil
	}

	attendu := strings.TrimSpace(c.Expect)
	if droits != attendu {
		return false, ecartConstate("ACL "+spec+" sur "+chemin, attendu, droits), nil
	}
	// L'entrée est juste, le masque la rabote. La politique n'est pas en vigueur.
	if effectifs != "" && effectifs != droits {
		return false, "ACL " + spec + " sur " + chemin + " : " + droits +
			" accorde mais " + effectifs + " effectif — le masque de l'ACL la limite", nil
	}
	return true, "", nil
}

// decouperCibleACL sépare le chemin de la spécification d'entrée.
//
// Découpage sur le DERNIER séparateur : un chemin contenant « | » est
// pathologique mais légal sous Unix, alors qu'une spécification « u:alice » n'en
// contient jamais. Couper sur le premier casserait le premier cas, couper sur le
// dernier ne casse aucun des deux.
func decouperCibleACL(cible string) (chemin, spec string, ok bool) {
	i := strings.LastIndex(cible, "|")
	if i <= 0 || i == len(cible)-1 {
		return "", "", false
	}
	return cible[:i], cible[i+1:], true
}

// entreeACL retrouve une entrée nommée dans la sortie de getfacl.
//
// Les lignes « default: » sont IGNORÉES : elles décrivent ce qu'hériteront les
// fichiers créés ensuite, pas les droits en vigueur sur ce chemin. Les confondre
// ferait constater une entrée là où l'ACL d'accès a été retirée.
//
//	user:alice:rw-
//	group:dev:r-x			#effective:r--
//	default:user:alice:rw-
func entreeACL(sortie, spec string) (droits, effectifs string, present bool) {
	prefixe := prefixeLongACL(spec)
	if prefixe == "" {
		return "", "", false
	}

	for _, ligne := range strings.Split(sortie, "\n") {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" || strings.HasPrefix(ligne, "#") || strings.HasPrefix(ligne, "default:") {
			continue
		}
		if !strings.HasPrefix(ligne, prefixe) {
			continue
		}

		reste := strings.TrimPrefix(ligne, prefixe)
		// L'annotation d'effectivité suit les droits, après une tabulation.
		valeur, annotation, aEffectif := strings.Cut(reste, "#effective:")
		droits = strings.TrimSpace(valeur)
		if aEffectif {
			effectifs = strings.TrimSpace(annotation)
		}
		return droits, effectifs, true
	}
	return "", "", false
}

// prefixeLongACL traduit « u:alice » en « user:alice: », la forme que getfacl
// écrit. setfacl accepte les deux abréviations, getfacl n'en rend qu'une.
func prefixeLongACL(spec string) string {
	genre, nom, ok := strings.Cut(spec, ":")
	if !ok || nom == "" {
		return ""
	}
	switch genre {
	case "u", "user":
		return "user:" + nom + ":"
	case "g", "group":
		return "group:" + nom + ":"
	}
	return ""
}
