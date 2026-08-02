package gpo

import (
	"fmt"
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
		rich := fmt.Sprintf(`rule family="ipv4" source address="%s" port port="%s" protocol="%s" %s`,
			source, port, proto, map[bool]string{true: "reject", false: "accept"}[drop])
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
	if remove {
		// nftables ne sait pas supprimer une règle par sa description : il faut
		// son handle. Plutôt que de le chercher — fragile, et dépendant du
		// format de sortie — on vide la chaîne et on laisse le prochain cycle
		// reposer les règles encore actives. L'agent réapplique l'intégralité
		// des modules dont l'empreinte a changé, donc l'état converge.
		if _, err := runCommand("nft", "flush", "chain", "inet", vaultaireNftTable, "input"); err != nil {
			return "", fmt.Errorf("purge de la chaine impossible : %v", err)
		}
		return "regle " + spec + " retiree (chaine purgee, les regles actives seront reposees)", nil
	}

	args := []string{"add", "rule", "inet", vaultaireNftTable, "input"}
	if source != "" {
		args = append(args, "ip", "saddr", source)
	}
	args = append(args, proto, "dport", port, verdict)

	if _, err := runCommand("nft", args...); err != nil {
		return "", err
	}
	return describeFirewallResult("nftables", spec, source, action, false), nil
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
