package action

import (
	"fmt"
	"strconv"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	newclient "vaultaire/ducky-network/new_client"
)

// Actions sur les machines du parc.
//
// # Une asymétrie à connaître
//
// Créer une machine ne crée pas un enregistrement au sens ordinaire : cela
// GÉNÈRE UNE IDENTITÉ — un identifiant et une paire de clés — que l'on
// installera ensuite sur un poste. Supprimer une machine, à l'inverse, ne
// désinstalle rien : l'agent continue de tourner là-bas, il ne sera simplement
// plus reconnu.
//
// Cette asymétrie explique pourquoi la suppression rend un message qui le dit.
// Un administrateur qui lit « Machine supprimée » sans autre précision peut
// croire le poste nettoyé, alors que l'agent y reste installé et qu'un compte
// local peut y subsister.

// EnregistrerActionsClient ajoute les actions machine au registre.
func EnregistrerActionsClient(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "client.create",
		CleRBAC: "write:create:client",
		// La machine n'existe pas encore : aucun domaine dont déduire la portée.
		Portee:   PorteeGlobale,
		Resume:   "génère l'identité d'une nouvelle machine",
		Executer: creerClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client.update",
		CleRBAC:  "write:update:client",
		Portee:   PorteeClient,
		Resume:   "met à jour l'inventaire d'une machine",
		Executer: modifierClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client.delete",
		CleRBAC:  "write:delete:client",
		Portee:   PorteeClient,
		Resume:   "retire une machine de l'annuaire",
		Executer: supprimerClient,
	})
}

// creerClient génère l'identité d'une machine.
//
// Le TYPE n'est pas demandé : ce chemin ne peut créer qu'un client basic. Un
// client service s'enrôle lui-même avec sa propre paire de clés — il ne se crée
// pas depuis l'administration, puisque sa clé privée ne doit jamais quitter
// l'hôte qui l'utilisera.
func creerClient(_ Appelant, p Params) (Resultat, error) {
	// Le web lisait `is_serveur == "1"`, une convention de formulaire. On
	// accepte aussi les formes qu'écrirait une ligne de commande, sans quoi
	// l'action ne serait utilisable que depuis le navigateur.
	estServeur, err := booleenPermissif(p.Get("is_serveur"))
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur is_serveur invalide : %w", err)
	}

	computeurID, err := newclient.GenerateClientSoftware(estServeur)
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création de la machine : %w", err)
	}

	return Resultat{
		Message: fmt.Sprintf("Machine créée, identifiant %s.", computeurID),
		Donnees: map[string]string{"computeur_id": computeurID},
	}, nil
}

// booleenPermissif accepte « 1 » en plus des formes de booleen().
//
// Le formulaire des machines emploie la valeur « 1 » là où celui des groupes
// emploie « on ». Les deux conventions coexistent dans les gabarits ; les
// unifier demanderait de les modifier tous, ce qui n'est pas le sujet de ce
// portage — et une valeur mal interprétée créerait ici une machine du mauvais
// type, ce qui ne se verrait qu'à l'usage.
func booleenPermissif(v string) (bool, error) {
	return booleen(v)
}

// modifierClient met à jour l'inventaire matériel.
//
// Les champs absents ne sont pas touchés. L'ancienne version web passait
// systématiquement les quatre valeurs du formulaire : un formulaire partiel
// effaçait donc les champs qu'il ne portait pas — un inventaire réduit à des
// chaînes vides après une simple correction de nom d'hôte.
func modifierClient(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("computeur_id")
	if cible == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	db := database.GetDatabase()
	courant, err := dbclients.Command_GET_ClientByComputeurID(db, cible)
	if err != nil || courant == nil {
		return Resultat{}, fmt.Errorf("machine %q introuvable", cible)
	}

	hostname := valeurOuCourante(p, "hostname", courant.Hostname)
	systeme := valeurOuCourante(p, "os", courant.OS)
	ram := valeurOuCourante(p, "ram", courant.RAM)
	// Processeur est un entier en base mais une chaîne dans UpdateHostname.
	// La conversion est faite ici, une fois, plutôt que laissée à chaque
	// appelant — c'est le genre d'écart qui produit un « 0 » là où il y avait
	// un nombre de cœurs.
	proc := valeurOuCourante(p, "proc", strconv.Itoa(courant.Processeur))

	if err := dbclients.UpdateHostname(db, cible, hostname, systeme, ram, proc); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la mise à jour de la machine %q : %w", cible, err)
	}

	res := Resultat{Message: fmt.Sprintf("Machine %s mise à jour.", cible)}
	if maj, err := dbclients.Command_GET_ClientByComputeurID(db, cible); err == nil {
		res.Donnees = maj
	}
	return res, nil
}

// valeurOuCourante rend la valeur fournie, ou celle déjà en base si le champ
// n'a pas été transmis.
//
// Presente et non Get : un champ transmis vide veut dire « effacer », un champ
// absent veut dire « ne pas toucher ». Les confondre est précisément ce qui
// effaçait l'inventaire.
func valeurOuCourante(p Params, nom, courante string) string {
	if p.Presente(nom) {
		return p.Get(nom)
	}
	return courante
}

// supprimerClient retire la machine de l'annuaire.
func supprimerClient(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("computeur_id")
	if cible == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	if err := dbclients.Command_DELETE_ClientWithComputeurID(database.GetDatabase(), cible); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la machine %q : %w", cible, err)
	}

	// Le message dit ce que la suppression NE fait PAS.
	//
	// L'ancienne version rendait « Client supprimé. », ce qui laisse croire au
	// nettoyage du poste. Or l'agent y tourne toujours, avec sa clé privée et
	// les comptes locaux qu'il a créés — il ne sera simplement plus reconnu par
	// le core. Un administrateur qui compte sur cette action pour retirer un
	// poste compromis se tromperait.
	return Resultat{
		Message: fmt.Sprintf(
			"Machine %s retirée de l'annuaire. L'agent reste installé sur le poste et "+
				"n'est pas désinstallé ; les comptes locaux qu'il a créés y subsistent.",
			cible),
	}, nil
}
