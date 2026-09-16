package clienttype

import "testing"

// Le rôle qu'un programme prend dans le cluster.
//
// # Ce que ces tests gardent
//
// `handleRegisterHost` lisait le rôle dans le CONTENU de la trame 04_01. Or
// `NoeudsPourAgents` sert les rôles « core » et « proxy » aux agents AVEC LEUR
// EMPREINTE : un proxy qui s'annonçait « core » faisait apprendre son empreinte
// au parc comme celle d'un serveur d'authentification.
//
// Un champ que le client remplit et que le serveur croit n'est pas une donnée,
// c'est une permission.

// TestAucunTypeNeProduitLeRoleCore.
//
// LE test. Il ne porte pas sur les types d'aujourd'hui mais sur TOUT le
// catalogue, présent et à venir : le jour où un type est ajouté, ce test le
// couvre sans que personne y pense.
//
// « core » ne peut être le rôle d'aucun type parce qu'un core n'est pas au
// catalogue — il ne peut pas se juger lui-même — et qu'il n'entre dans
// cluster_nodes que par son propre processus, sans session.
func TestAucunTypeNeProduitLeRoleCore(t *testing.T) {
	for _, d := range All() {
		if RoleCluster(d.Name) == "core" {
			t.Errorf("le type %q produit le rôle « core » : un nœud de ce type serait "+
				"annoncé aux agents comme serveur d'authentification, avec son empreinte",
				d.Name)
		}
	}
	// Et par la porte de service : une chaîne quelconque non plus.
	for _, entree := range []string{"core", "Core", "CORE", " core ", "vaultaire_core", ""} {
		if RoleCluster(entree) == "core" {
			t.Errorf("RoleCluster(%q) rend « core »", entree)
		}
	}
}

// TestSeulLeProxyEstUnNoeudDuCluster.
//
// Un type sans rôle de nœud ne s'enregistre pas par 04_01 — le gestionnaire
// refuse. C'est la forme fail-closed : ajouter un type au catalogue ne lui donne
// aucune place dans cluster_nodes tant que personne ne l'a décidé ici.
func TestSeulLeProxyEstUnNoeudDuCluster(t *testing.T) {
	if RoleCluster(Proxy) != "proxy" {
		t.Errorf("RoleCluster(%q) = %q, attendu « proxy »", Proxy, RoleCluster(Proxy))
	}
	for _, autre := range []string{Client, Web, "inconnu", ""} {
		if r := RoleCluster(autre); r != "" {
			t.Errorf("RoleCluster(%q) = %q : ce type prendrait une place dans "+
				"cluster_nodes sans que ce soit voulu", autre, r)
		}
	}
}

// TestLeRoleEstInsensibleAuxEspaces.
//
// Le type vient de la base, par la poignée de main. Un espace en fin de colonne
// ferait rendre « » — donc refuser l'enregistrement d'un proxy parfaitement
// légitime, et le symptôme serait « ce type de client ne s'enregistre pas comme
// nœud », qui envoie chercher du côté du catalogue.
func TestLeRoleEstInsensibleAuxEspaces(t *testing.T) {
	for _, entree := range []string{" " + Proxy, Proxy + " ", "\t" + Proxy + "\n"} {
		if RoleCluster(entree) != "proxy" {
			t.Errorf("RoleCluster(%q) = %q, attendu « proxy »", entree, RoleCluster(entree))
		}
	}
}

// TestSeulUnTypeQuiEmet0401APrendUnRole.
//
// Cohérence entre les deux moitiés du contrôle. Un type qui aurait un rôle de
// nœud sans le droit d'émettre 04_01 ne pourrait jamais s'enregistrer : le rôle
// serait du code mort, et sa présence laisserait croire le contraire.
//
// L'inverse est le vrai risque : un type autorisé à émettre 04_01 mais sans
// rôle est refusé à l'exécution, sans que rien ne le signale à la lecture du
// catalogue.
func TestSeulUnTypeQuiEmet0401APrendUnRole(t *testing.T) {
	for _, d := range All() {
		role := RoleCluster(d.Name)
		emet := MayEmit(d.Name, "04_01")

		if role != "" && !emet {
			t.Errorf("le type %q a le rôle %q mais n'a pas le droit d'émettre 04_01 : "+
				"il ne pourra jamais s'enregistrer", d.Name, role)
		}
		if emet && role == "" {
			t.Errorf("le type %q peut émettre 04_01 mais n'a aucun rôle de nœud : "+
				"son enregistrement sera refusé a l'execution", d.Name)
		}
	}
}
