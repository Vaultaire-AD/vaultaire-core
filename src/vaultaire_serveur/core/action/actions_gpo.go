package action

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
)

// Écritures sur les GPO.
//
// # Le dernier lot, et pourquoi il était à part
//
// Les GPO avaient été exclues de la refonte : leur logique est spécifique, et
// une traduction hâtive aurait été pire que la duplication. Elles arrivent donc
// en dernier, dans leur propre fichier, pour être éprouvées ou rejetées seules.
//
// # Ce que porte une GPO
//
// Des règles sudo, des fichiers déposés en root, des restrictions de shell —
// appliquées à tout le parc visé, au démarrage et à chaque rafraîchissement.
// C'est l'objet le plus lourd de l'annuaire, et le contrôle de sa modification
// mérite d'être exact.
//
// # La règle qui gouverne toutes ces actions
//
// Une GPO couvre les domaines des groupes auxquels elle est LIÉE, et elle
// s'applique à tous à la fois. La modifier exige donc le droit sur CHACUN.
//
// Sans cela, la portée serait extensible : je lie la GPO à un groupe de mon
// domaine, ce qui me donne le droit d'écriture ; je la lie ensuite à un groupe
// d'un domaine que je ne contrôle pas, et je continue de passer les contrôles
// grâce au premier. Des règles sudo s'appliqueraient alors à un parc qui ne
// m'appartient pas.
//
// C'est le raisonnement que portait déjà checkGPORBAC dans le serveur web. Il
// est ici, donc partagé avec la ligne de commande — qui, elle, ne l'avait pas.

// EnregistrerActionsGPO ajoute les écritures GPO au registre.
func EnregistrerActionsGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "gpo.create",
		CleRBAC: "write:create:gpo",
		// Portée globale : une GPO qui n'existe pas encore n'est liée à aucun
		// groupe, donc ne couvre aucun domaine. Il n'y a rien de plus précis à
		// exiger, et exiger moins reviendrait à n'exiger rien.
		Portee:   PorteeGlobale,
		Resume:   "crée une GPO vide",
		Executer: creerGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:      "gpo.update",
		CleRBAC:  "write:update:gpo",
		Portee:   porteeGPO,
		Resume:   "modifie la description et l'activation d'une GPO",
		Executer: modifierGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:      "gpo.delete",
		CleRBAC:  "write:delete:gpo",
		Portee:   porteeGPO,
		Resume:   "supprime une GPO, ses modules et ses liaisons",
		Executer: supprimerGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:     "gpo.add_module",
		CleRBAC: "write:update:gpo",
		Portee:  porteeGPO,
		Resume:  "ajoute un module à une GPO",
		// write:update:gpo et non write:create:* : ajouter un module ne crée
		// pas une entité de l'annuaire, cela change ce que la GPO fait. Le
		// droit qui gouverne cet effet est celui de la modifier.
		Executer: ajouterModuleGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:      "gpo.update_module",
		CleRBAC:  "write:update:gpo",
		Portee:   porteeGPO,
		Resume:   "modifie les paramètres d'un module",
		Executer: modifierModuleGPO,
	})

	r.MustEnregistrer(Definition{
		Nom:      "gpo.delete_module",
		CleRBAC:  "write:update:gpo",
		Portee:   porteeGPO,
		Resume:   "retire un module d'une GPO",
		Executer: supprimerModuleGPO,
	})
}

// PorteeGPOEtGroupe exige le droit sur les domaines des DEUX.
//
// # Pourquoi l'union pour une liaison
//
// Lier une GPO à un groupe a deux effets, et chacun engage un périmètre
// différent :
//
//   - le groupe reçoit les règles de la GPO → ses domaines à lui sont touchés ;
//   - la GPO s'étend aux domaines du groupe → son périmètre à elle grandit.
//
// N'exiger que les domaines du GROUPE — ce que faisait group.add_gpo — laisse
// passer une manœuvre discrète : un délégué de paris lie une GPO de lyon à un
// groupe paris. La GPO couvre désormais paris ET lyon, et l'administrateur de
// lyon ne peut plus la modifier sans le droit sur paris. Il ne s'agit pas d'une
// élévation de privilège mais d'un VERROUILLAGE : on prive autrui de sa propre
// GPO, sans jamais toucher à ses droits.
//
// L'union interdit les deux sens. C'est plus strict qu'avant.
//
// À vérifier chez vous : un délégué qui rattachait à ses groupes des GPO
// venues d'un autre domaine perdra cette possibilité.
func PorteeGPOEtGroupe(p Params) ([]string, error) {
	domainesGroupe, errG := domainesDuGroupe(p.Get("group"))
	domainesGPO, errP := domainesDeLaGPO(p.Get("gpo"))

	if errG != nil {
		// Le groupe est la cible obligatoire : ne pas savoir le situer interdit
		// d'agir. L'erreur sur la GPO, elle, est tolérée — une GPO neuve n'a
		// simplement aucun domaine, ce qui n'est pas une anomalie.
		return domainesOuGlobal(nil, fmt.Errorf("groupe : %w", errG))
	}
	if errP != nil {
		domainesGPO = nil
	}
	return domainesOuGlobal(unionDomaines(domainesGroupe, domainesGPO), nil)
}

// --- création ----------------------------------------------------------------

func creerGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		nom = p.Get("name")
	}
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}

	// La portée d'application — machine ou user — est OBLIGATOIRE et sans
	// valeur par défaut.
	//
	// Choisir « machine » en silence donnerait une GPO qui s'applique au
	// démarrage de tous les postes visés, là où l'auteur en voulait une
	// appliquée à l'ouverture de session d'un utilisateur. La différence ne se
	// voit qu'au déploiement, sur le parc.
	brut := strings.ToLower(strings.TrimSpace(p.Get("scope")))
	if brut == "" {
		return Resultat{}, fmt.Errorf(
			"portée requise : une GPO est soit « machine », soit « user » — " +
				"aucune valeur par défaut, la différence se voit sur le parc")
	}
	portee := gpo.Scope(brut)
	if !gpo.IsValidPolicyScope(portee) {
		return Resultat{}, fmt.Errorf("portée %q invalide (attendu : machine ou user)", brut)
	}

	db := database.GetDatabase()
	if _, err := dbgpo.CreatePolicy(db, nom, portee, p.Get("description")); err != nil {
		return Resultat{}, fmt.Errorf("création de la GPO %q : %w", nom, err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a créé la GPO %s (portée %s)", a.Username, nom, portee))

	policy, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{Message: "GPO " + nom + " créée (relecture impossible : " + err.Error() + ")"}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("GPO %s créée (portée %s). Elle ne s'applique à personne "+
			"tant qu'elle n'est liée à aucun groupe.", nom, portee),
		Donnees: policy,
	}, nil
}

// --- modification et suppression ---------------------------------------------

func modifierGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}
	db := database.GetDatabase()

	policy, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("GPO %q introuvable : %w", nom, err)
	}

	// « enabled » absent vaut FAUX, comme une case décochée.
	//
	// C'est le comportement d'un formulaire HTML : une case non cochée n'est
	// pas envoyée. Traiter l'absence comme « inchangé » ferait qu'on ne
	// pourrait jamais désactiver une GPO depuis le web.
	actif := estVrai(p.Get("enabled"))

	if err := dbgpo.UpdatePolicyMeta(db, policy.ID, p.Get("description"), actif); err != nil {
		return Resultat{}, fmt.Errorf("mise à jour de la GPO %q : %w", nom, err)
	}

	// L'activation change ce qui s'applique au parc : elle mérite sa trace.
	if actif != policy.Enabled {
		etat := "désactivée"
		if actif {
			etat = "activée"
		}
		logs.Write_Log("SECURITY", fmt.Sprintf("%s a %s la GPO %s", a.Username, etat, nom))
	}

	relue, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{Message: "GPO " + nom + " mise à jour."}, nil
	}
	return Resultat{Message: "GPO " + nom + " mise à jour.", Donnees: relue}, nil
}

func supprimerGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}
	db := database.GetDatabase()

	if err := dbgpo.DeletePolicyByName(db, nom); err != nil {
		return Resultat{}, fmt.Errorf("suppression de la GPO %q : %w", nom, err)
	}

	// Vérification APRÈS coup.
	//
	// DeletePolicyByName peut rendre nil sans avoir rien supprimé — sur une
	// clause WHERE qui ne correspond à rien, par exemple. Annoncer un succès
	// dans ce cas laisserait croire qu'une politique dangereuse a été retirée
	// du parc alors qu'elle s'y applique toujours.
	if dbgpo.PolicyExists(db, nom) {
		return Resultat{}, fmt.Errorf(
			"la GPO %q existe encore après suppression : elle continue de s'appliquer au parc", nom)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a supprimé la GPO %s (modules et liaisons de groupe inclus)", a.Username, nom))

	return Resultat{Message: fmt.Sprintf(
		"GPO %s supprimée : modules et liaisons de groupe inclus.", nom)}, nil
}

// --- modules -----------------------------------------------------------------

func ajouterModuleGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	typeModule := p.Get("module_type")
	if nom == "" || typeModule == "" {
		return Resultat{}, fmt.Errorf("nom de GPO et type de module requis")
	}
	db := database.GetDatabase()

	policy, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("GPO %q introuvable : %w", nom, err)
	}

	params, err := ParametresDeModule(typeModule, p)
	if err != nil {
		return Resultat{}, err
	}

	if _, err := dbgpo.AddModule(db, policy.ID, typeModule, params); err != nil {
		return Resultat{}, fmt.Errorf("module refusé : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a ajouté le module %s à la GPO %s", a.Username, typeModule, nom))

	return Resultat{Message: fmt.Sprintf("Module %s ajouté à %s.", typeModule, nom)}, nil
}

func modifierModuleGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}
	id, err := strconv.Atoi(p.Get("module_id"))
	if err != nil {
		return Resultat{}, fmt.Errorf("identifiant de module invalide : %q", p.Get("module_id"))
	}
	db := database.GetDatabase()

	policy, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("GPO %q introuvable : %w", nom, err)
	}

	existant, proprietaire, err := dbgpo.GetModuleByID(db, id)
	if err != nil {
		return Resultat{}, fmt.Errorf("module %d introuvable : %w", id, err)
	}

	// Le module doit appartenir à la GPO visée.
	//
	// Sans ce contrôle, un identifiant forgé permettrait de modifier le module
	// d'une AUTRE GPO — celle dont on vient de passer le contrôle de droits
	// n'étant pas celle qu'on modifie. La portée vérifiée porterait alors sur
	// une GPO sans rapport avec l'écriture.
	if proprietaire != policy.ID {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de modifier le module %d hors de la GPO %s", a.Username, id, nom))
		return Resultat{}, fmt.Errorf("le module %d n'appartient pas à la GPO %q", id, nom)
	}

	params, err := ParametresDeModule(existant.Type, p)
	if err != nil {
		return Resultat{}, err
	}

	if err := dbgpo.UpdateModuleParams(db, id, params); err != nil {
		return Resultat{}, fmt.Errorf("module refusé : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a modifié le module %d (%s) de la GPO %s", a.Username, id, existant.Type, nom))

	return Resultat{Message: fmt.Sprintf("Module %s mis à jour.", existant.Type)}, nil
}

func supprimerModuleGPO(a Appelant, p Params) (Resultat, error) {
	nom := p.Get("gpo")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de GPO requis")
	}
	id, err := strconv.Atoi(p.Get("module_id"))
	if err != nil {
		return Resultat{}, fmt.Errorf("identifiant de module invalide : %q", p.Get("module_id"))
	}
	db := database.GetDatabase()

	policy, err := dbgpo.GetPolicyByName(db, nom)
	if err != nil {
		return Resultat{}, fmt.Errorf("GPO %q introuvable : %w", nom, err)
	}

	// Même garde que pour la modification, et pour la même raison.
	_, proprietaire, err := dbgpo.GetModuleByID(db, id)
	if err != nil {
		return Resultat{}, fmt.Errorf("module %d introuvable : %w", id, err)
	}
	if proprietaire != policy.ID {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"%s tente de supprimer le module %d hors de la GPO %s", a.Username, id, nom))
		return Resultat{}, fmt.Errorf("le module %d n'appartient pas à la GPO %q", id, nom)
	}

	if err := dbgpo.DeleteModule(db, id); err != nil {
		return Resultat{}, fmt.Errorf("suppression du module %d : %w", id, err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a supprimé le module %d de la GPO %s", a.Username, id, nom))

	return Resultat{Message: "Module retiré."}, nil
}

// ParametresDeModule extrait les paramètres d'un module d'après son SCHÉMA.
//
// # Pourquoi la validation est ici et non dans la façade
//
// Elle vivait dans collectModuleParams, côté web, et nulle part ailleurs. La
// ligne de commande n'ajoute pas encore de module — mais le jour où elle le
// fera, elle aurait écrit en base des paramètres qu'aucun schéma ne couvre :
// des clés que l'agent client ignore, donc un module qui ne fait rien, sans
// que rien ne le signale.
//
// Les champs sont lus DEPUIS LE SCHÉMA et non depuis ce que l'appelant envoie :
// un paramètre non déclaré est simplement ignoré, et un champ déclaré absent
// devient vide plutôt que manquant.
//
// Exportée pour que l'interface web construise ses formulaires sur la même
// source.
func ParametresDeModule(typeModule string, p Params) (map[string]string, error) {
	schema, connu := gpo.SchemaFor(typeModule)
	if !connu {
		return nil, fmt.Errorf("type de module %q inconnu du catalogue", typeModule)
	}

	params := make(map[string]string, len(schema.Fields))
	for _, f := range schema.Fields {
		// Préfixe « p_ » : c'est la convention des formulaires web, conservée
		// pour ne pas avoir à réécrire les gabarits. La valeur sans préfixe est
		// acceptée aussi, pour que la ligne de commande n'ait pas à imiter une
		// convention HTML.
		brut := p.Get("p_" + f.Name)
		if brut == "" {
			brut = p.Get(f.Name)
		}

		if f.Type == gpo.FieldBool {
			// Une case à cocher non cochée n'est pas envoyée : son absence vaut
			// « false », et non « inchangé ».
			params[f.Name] = strconv.FormatBool(estVrai(brut))
			continue
		}
		params[f.Name] = brut
	}
	return params, nil
}

// estVrai interprète les formes qu'une case à cocher peut prendre.
//
// « on » est ce qu'envoie un navigateur, « true » ce qu'écrit une API, « 1 » ce
// que tape un script. Les trois désignent la même intention ; n'en reconnaître
// qu'une ferait dépendre le résultat de la façade employée.
func estVrai(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "1", "oui", "yes":
		return true
	default:
		return false
	}
}
