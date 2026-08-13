package gpo

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Appliqueur du pare-feu.
//
// Appliqué en phase de configuration système, donc APRÈS l'installation des
// paquets et AVANT le démarrage des services : un service qui démarre trouve le
// port déjà ouvert, plutôt que de commencer à écouter derrière un pare-feu
// fermé.
//
// PRINCIPE : les règles Vaultaire vivent dans un espace qui leur est propre —
// une zone firewalld dédiée, une table nftables nommée. Elles ne sont jamais
// mélangées aux règles saisies à la main par un administrateur. Retirer une GPO
// ne doit pas emporter avec elle une règle que personne n'avait demandé de
// supprimer, et inversement un `nft flush ruleset` local ne doit pas laisser
// croire que la politique est toujours appliquée.

// vaultaireNftTable est la table nftables réservée aux règles de GPO.
const vaultaireNftTable = "vaultaire_gpo"

// applyFirewallRule ouvre ou ferme un port.
func applyFirewallRule(ctx Context, m Module) (string, error) {
	port := strings.TrimSpace(m.Param("port"))
	proto := strings.TrimSpace(m.Param("protocol"))
	if port == "" || proto == "" {
		return "", fmt.Errorf("port ou protocole manquant")
	}
	source := strings.TrimSpace(m.Param("source"))
	action := m.Param("action")
	remove := m.Param("state") == "absent"

	switch detectFirewallBackend() {
	case "firewalld":
		return applyFirewalld(port, proto, source, action, remove)
	case "nft":
		return applyNftables(port, proto, source, action, remove)
	default:
		// Ni firewalld ni nftables : plutôt que d'installer un pare-feu à
		// l'insu de l'administrateur, on remonte un échec explicite. Le
		// module Paquet est là pour ça, et son absence dans la politique est
		// une décision qui appartient à celui qui l'a écrite.
		return "", fmt.Errorf("aucun pare-feu gere trouve (firewalld ou nftables attendu)")
	}
}

// detectFirewallBackend identifie le pare-feu en service.
//
// firewalld est testé en premier, et seulement s'il est ACTIF : le paquet peut
// être installé sans tourner, auquel cas ses commandes réussissent en écrivant
// une configuration que rien n'applique — le port resterait fermé alors que le
// module rapporterait un succès.
func detectFirewallBackend() string {
	if out, err := runCommand("systemctl", "is-active", "firewalld"); err == nil &&
		strings.TrimSpace(out) == "active" {
		return "firewalld"
	}
	if _, err := runCommand("nft", "--version"); err == nil {
		return "nft"
	}
	return ""
}

// applyFirewalld pose la règle via firewall-cmd, dans la zone par défaut.
func applyFirewalld(port, proto, source, action string, remove bool) (string, error) {
	// firewalld exprime « refuser » par l'absence de la règle d'autorisation :
	// sa politique par défaut est déjà le rejet. Poser une règle « deny »
	// explicite demanderait une rich rule, dont la syntaxe varie selon les
	// versions ; retirer l'autorisation produit le même effet observable.
	drop := remove || action == "deny"

	verb := "--add-port"
	if drop {
		verb = "--remove-port"
	}
	spec := port + "/" + proto

	args := []string{"--permanent", verb + "=" + spec}
	if source != "" {
		// Une source précise demande une rich rule : la règle simple ne sait pas
		// restreindre l'origine.
		//
		// LE VERDICT SUIT `action`, PAS `drop`. firewalld supprime une rich rule
		// par comparaison EXACTE de son texte : pour retirer une règle, il faut
		// lui repasser mot pour mot celle qui a été posée.
		//
		// La version précédente composait le texte avec `drop`, qui vaut vrai dès
		// que l'on supprime. Elle demandait donc à firewalld de retirer une règle
		// « reject » alors que la règle installée disait « accept » : aucune ne
		// correspondait, firewalld répondait que la règle n'était pas là, et
		// l'autorisation restait en place. Une GPO retirée laissait le port
		// ouvert à sa source — exactement l'inverse de ce qu'on demandait.
		verdict := "accept"
		if action == "deny" {
			verdict = "reject"
		}
		rich := fmt.Sprintf(`rule family="ipv4" source address="%s" port port="%s" protocol="%s" %s`,
			source, port, proto, verdict)
		richVerb := "--add-rich-rule"
		if remove {
			richVerb = "--remove-rich-rule"
		}
		args = []string{"--permanent", richVerb + "=" + rich}
	}

	if _, err := runCommand("firewall-cmd", args...); err != nil {
		return "", err
	}
	// --permanent n'agit que sur la configuration : sans rechargement, la règle
	// ne prend effet qu'au prochain redémarrage du service.
	if _, err := runCommand("firewall-cmd", "--reload"); err != nil {
		return "", fmt.Errorf("rechargement de firewalld impossible : %v", err)
	}

	return describeFirewallResult("firewalld", spec, source, action, remove), nil
}

// applyNftables pose la règle dans une table dédiée à Vaultaire.
func applyNftables(port, proto, source, action string, remove bool) (string, error) {
	// La table et la chaîne sont créées si besoin. `add` est idempotent sur une
	// table existante, ce qui permet de ne pas distinguer premier passage et
	// passages suivants.
	if _, err := runCommand("nft", "add", "table", "inet", vaultaireNftTable); err != nil {
		return "", fmt.Errorf("creation de la table %s impossible : %v", vaultaireNftTable, err)
	}
	if _, err := runCommand("nft", "add", "chain", "inet", vaultaireNftTable, "input",
		"{ type filter hook input priority 0 ; }"); err != nil {
		return "", fmt.Errorf("creation de la chaine input impossible : %v", err)
	}

	verdict := "accept"
	if action == "deny" {
		verdict = "drop"
	}

	spec := port + "/" + proto
	cle := cleRegleNft(proto, port, source)

	if remove {
		return retirerRegleNft(cle, spec)
	}

	args := []string{"add", "rule", "inet", vaultaireNftTable, "input"}
	if source != "" {
		args = append(args, "ip", "saddr", source)
	}
	// Le COMMENTAIRE est ce qui rend la règle retrouvable plus tard.
	//
	// nftables ne sait pas supprimer une règle par sa description : il faut son
	// handle, attribué à la pose et connu de lui seul. Sans repère, on ne peut
	// désigner la règle qu'en la décrivant — et la décrire suppose de reproduire
	// exactement la forme que nft a choisi d'afficher, qui varie.
	//
	// Le commentaire est stable, choisi par nous, et nft l'expose dans sa sortie
	// JSON. C'est le seul lien fiable entre un module de GPO et la règle qu'il a
	// posée.
	args = append(args, proto, "dport", port, verdict, "comment", `"`+cle+`"`)

	if _, err := runCommand("nft", args...); err != nil {
		return "", err
	}
	return describeFirewallResult("nftables", spec, source, action, false), nil
}

// cleRegleNft identifie une règle indépendamment de son verdict.
//
// Le verdict n'entre PAS dans la clé, à dessein : une règle posée en « accept »
// puis déclarée absente alors que le module est passé à « deny » doit quand même
// se retrouver. Ce qu'on veut exprimer est « cette règle de port ne doit plus
// exister », pas « cette règle exactement telle qu'elle était ».
func cleRegleNft(proto, port, source string) string {
	if source == "" {
		source = "any"
	}
	return "vlt:" + proto + ":" + port + ":" + source
}

// regleNft : la partie de la sortie JSON de nft qui nous intéresse.
type regleNft struct {
	Rule struct {
		Handle  int    `json:"handle"`
		Comment string `json:"comment"`
	} `json:"rule"`
}

// retirerRegleNft supprime UNE règle, par son handle.
//
// # Ce que faisait la version précédente
//
// Elle vidait la chaîne entière — `nft flush chain` — en expliquant que « le
// prochain cycle reposera les règles actives, donc l'état converge ».
//
// Il ne converge pas. `apply.go` saute les modules dont l'empreinte n'a pas
// changé (« empreinte identique ») : un module dont rien n'a bougé n'est jamais
// réappliqué. Retirer UNE règle de pare-feu supprimait donc TOUTES les autres,
// définitivement — jusqu'à ce qu'un changement sans rapport vienne les remettre.
//
// Et rien ne le signalait : le scan de conformité ne couvre que les fichiers,
// pas les effets de commande. La machine était déclarée conforme, pare-feu grand
// ouvert.
//
// # Pourquoi le JSON
//
// `nft -j` est l'interface destinée aux programmes, et le handle y est un
// entier, pas un fragment de ligne à découper. Analyser la sortie texte
// dépendrait d'une mise en forme que nft ne s'engage pas à conserver.
func retirerRegleNft(cle, spec string) (string, error) {
	sortie, err := runCommand("nft", "-j", "list", "chain", "inet", vaultaireNftTable, "input")
	if err != nil {
		// La table peut ne pas exister — rien n'a jamais été posé. Ce n'est pas
		// un échec : l'état demandé est déjà celui du système.
		return "regle " + spec + " absente (aucune table " + vaultaireNftTable + ")", nil
	}

	var doc struct {
		Nftables []regleNft `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(sortie), &doc); err != nil {
		// On NE VIDE PAS la chaîne en repli. Échouer franchement laisse le
		// pare-feu tel qu'il est et fait remonter le module en erreur ; purger
		// « au cas où » ouvrirait le parc pour cacher une sortie illisible.
		return "", fmt.Errorf("sortie JSON de nft illisible : %v", err)
	}

	handle := -1
	for _, r := range doc.Nftables {
		if r.Rule.Comment == cle {
			handle = r.Rule.Handle
			break
		}
	}
	if handle < 0 {
		// Idempotent : la règle n'est pas là, l'état voulu est atteint.
		//
		// ⚠️ Les règles posées AVANT l'introduction du commentaire n'en portent
		// pas et ne se retrouvent donc pas ici. Elles subsistent jusqu'à un
		// `nft flush chain inet vaultaire_gpo input` fait à la main, une fois.
		// C'est le prix de ne plus purger automatiquement, et il est préférable :
		// une règle de trop se voit, une règle manquante non.
		return "regle " + spec + " deja absente", nil
	}

	if _, err := runCommand("nft", "delete", "rule", "inet", vaultaireNftTable, "input",
		"handle", strconv.Itoa(handle)); err != nil {
		return "", fmt.Errorf("suppression de la regle %s impossible : %v", spec, err)
	}
	return "regle " + spec + " retiree", nil
}

// describeFirewallResult produit le détail rapporté au serveur.
func describeFirewallResult(backend, spec, source, action string, removed bool) string {
	var b strings.Builder
	if removed {
		b.WriteString("retire ")
	} else if action == "deny" {
		b.WriteString("bloque ")
	} else {
		b.WriteString("ouvert ")
	}
	b.WriteString(spec)
	if source != "" {
		b.WriteString(" depuis " + source)
	}
	b.WriteString(" (" + backend + ")")
	return b.String()
}
