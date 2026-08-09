package action

import (
	"fmt"
	"strings"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	dbclients "vaultaire/core/database/db_clients"
	dbgpo "vaultaire/core/database/db_gpo"
	dbgroups "vaultaire/core/database/db_groups"
	dbpermission "vaultaire/core/database/db_permission"
)

// Actions sur les groupes.
//
// # Ce que ce fichier corrige, au-delà du doublon
//
// Douze actions, toutes écrites sur le même motif côté web :
//
//	case "add_user":
//	    u := r.FormValue("username")
//	    if u != "" && dbgroups.Command_ADD_UserToGroup(db, u, targetGroup) == nil {
//	        detailData.Message = "Utilisateur ajouté."
//	        ...
//	    } else if u != "" {
//	        detailData.Message = "Erreur ajout (déjà membre ?)."
//	    }
//
// Trois défauts s'y logent, et ils sont systématiques :
//
//  1. PARAMÈTRE VIDE, SILENCE TOTAL. Le formulaire soumis sans sélection ne
//     produit aucun message. L'administrateur clique, la page se recharge
//     identique, et rien ne lui dit pourquoi.
//
//  2. ERREUR AVALÉE. Pour remove_user, add_client et remove_client, il n'y a
//     pas de branche `else` : l'échec de l'appel à la base ne produit aucun
//     message. L'action a échoué, la page affirme le contraire par son silence.
//
//  3. CAUSE DEVINÉE. « Erreur ajout (déjà membre ?) » est une hypothèse, pas un
//     diagnostic. L'erreur réelle de la base — contrainte violée, groupe
//     inexistant, connexion perdue — est jetée.
//
// Ici, une action rend une erreur ; l'appelant l'affiche. Les trois défauts
// disparaissent ensemble parce qu'ils venaient tous de la même chose : un
// résultat qu'on n'avait pas de moyen de rendre.
//
// # Un piège des signatures de la base
//
// L'ordre des arguments S'INVERSE entre l'ajout et le retrait :
//
//	Command_ADD_UserPermissionToGroup(db, permission, groupe)
//	Command_Remove_UserPermissionFromGroup(db, groupe, permission)
//
// Idem pour les permissions client. Une inversion ne produit aucune erreur de
// compilation — les deux paramètres sont des chaînes — et se traduit par une
// opération sur des entités qui n'existent pas, donc par un silence.
//
// Les appels ci-dessous nomment leurs arguments en commentaire à chaque fois
// que l'ordre diffère. C'est verbeux, et c'est délibéré.

// EnregistrerActionsGroupe ajoute les actions de ce fichier au registre.
func EnregistrerActionsGroupe(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "group.create",
		CleRBAC: "write:create:group",
		// Le groupe n'existe pas encore : aucun domaine dont déduire la portée.
		Portee:   PorteeGlobale,
		Resume:   "crée un groupe dans un domaine",
		Executer: creerGroupe,
	})

	r.MustEnregistrer(Definition{
		Nom:      "group.delete",
		CleRBAC:  "write:delete:group",
		Portee:   PorteeGroupe,
		Resume:   "supprime un groupe",
		Executer: supprimerGroupe,
	})

	// --- membres et machines ---------------------------------------------
	//
	// Les clés RBAC portent sur l'entité RATTACHÉE, pas sur le groupe. Ajouter
	// un utilisateur à un groupe lui donne les droits de ce groupe : c'est bien
	// l'utilisateur qu'on modifie. Exiger « write:update:group » laisserait un
	// délégué distribuer des droits à des comptes qu'il n'administre pas.

	r.MustEnregistrer(Definition{
		Nom:      "group.add_user",
		CleRBAC:  "write:add:user",
		Portee:   PorteeGroupeEtUtilisateur,
		Resume:   "ajoute un utilisateur à un groupe",
		Executer: rattacher("utilisateur", "username", ajouterUtilisateurAuGroupe),
	})
	r.MustEnregistrer(Definition{
		Nom:      "group.remove_user",
		CleRBAC:  "write:delete:user",
		Portee:   PorteeGroupeEtUtilisateur,
		Resume:   "retire un utilisateur d'un groupe",
		Executer: detacher("utilisateur", "username", retirerUtilisateurDuGroupe),
	})

	r.MustEnregistrer(Definition{
		Nom:      "group.add_client",
		CleRBAC:  "write:add:client",
		Portee:   PorteeGroupeEtClient,
		Resume:   "ajoute une machine à un groupe",
		Executer: rattacher("machine", "computeur_id", ajouterClientAuGroupe),
	})
	r.MustEnregistrer(Definition{
		Nom:      "group.remove_client",
		CleRBAC:  "write:delete:client",
		Portee:   PorteeGroupeEtClient,
		Resume:   "retire une machine d'un groupe",
		Executer: detacher("machine", "computeur_id", retirerClientDuGroupe),
	})

	// --- permissions ------------------------------------------------------

	r.MustEnregistrer(Definition{
		Nom:      "group.add_permission",
		CleRBAC:  "write:add:permission",
		Portee:   PorteeGroupe,
		Resume:   "attribue une permission utilisateur à un groupe",
		Executer: rattacher("permission", "permission", ajouterPermissionAuGroupe),
	})
	r.MustEnregistrer(Definition{
		Nom: "group.remove_permission",
		// L'ancienne table web employait ici « write:delete:group », ce qui
		// paraît être une faute de recopie : retirer une permission n'est pas
		// supprimer le groupe. « write:delete:permission » est retenu, cohérent
		// avec l'ajout et avec les permissions client.
		//
		// Conséquence : un délégué qui pouvait retirer des permissions parce
		// qu'il détenait write:delete:group ne le pourra plus sans
		// write:delete:permission. À vérifier sur vos groupes délégués.
		CleRBAC:  "write:delete:permission",
		Portee:   PorteeGroupe,
		Resume:   "retire une permission utilisateur d'un groupe",
		Executer: detacher("permission", "permission", retirerPermissionDuGroupe),
	})

	r.MustEnregistrer(Definition{
		Nom:      "group.add_client_permission",
		CleRBAC:  "write:add:permission",
		Portee:   PorteeGroupe,
		Resume:   "attribue une permission client à un groupe",
		Executer: rattacher("permission client", "client_permission", ajouterPermissionClientAuGroupe),
	})
	r.MustEnregistrer(Definition{
		Nom:      "group.remove_client_permission",
		CleRBAC:  "write:delete:permission",
		Portee:   PorteeGroupe,
		Resume:   "retire une permission client d'un groupe",
		Executer: detacher("permission client", "client_permission", retirerPermissionClientDuGroupe),
	})

	// --- GPO ---------------------------------------------------------------

	r.MustEnregistrer(Definition{
		Nom:     "group.add_gpo",
		CleRBAC: "write:add:gpo",
		// Union des domaines du groupe ET de la GPO — voir PorteeGPOEtGroupe.
		// N'exiger que ceux du groupe laissait verrouiller la GPO d'autrui.
		Portee:   PorteeGPOEtGroupe,
		Resume:   "lie une GPO à un groupe",
		Executer: rattacher("GPO", "gpo", lierGPOAuGroupe),
	})
	r.MustEnregistrer(Definition{
		Nom:      "group.remove_gpo",
		CleRBAC:  "write:delete:gpo",
		Portee:   PorteeGPOEtGroupe,
		Resume:   "délie une GPO d'un groupe",
		Executer: detacher("GPO", "gpo", delierGPODuGroupe),
	})

	// --- second facteur ----------------------------------------------------

	r.MustEnregistrer(Definition{
		Nom: "group.set_mfa_required",
		// write:mfa et non write:update:group : imposer ou lever le second
		// facteur d'un groupe entier pèse plus lourd que d'y ajouter un membre,
		// et relève de la même famille de décision que la réinitialisation d'un
		// compte. Cette clé venait déjà du web ; elle est conservée.
		CleRBAC:  "write:mfa",
		Portee:   PorteeGroupe,
		Resume:   "impose ou lève le second facteur pour les membres d'un groupe",
		Executer: reglerMFAGroupe,
	})
}

// --- le motif commun --------------------------------------------------------

// operationLien est une opération de rattachement ou de détachement.
type operationLien func(entite, groupe string) error

// rattacher construit une action « ajouter X au groupe G ».
//
// Le libellé et le nom du paramètre sont passés séparément pour que le message
// d'erreur nomme ce qui manque — « permission client requise » plutôt que
// « paramètre requis ». C'est ce qui distingue un message utile d'un message
// qui oblige à ouvrir le code.
func rattacher(libelle, param string, op operationLien) func(Appelant, Params) (Resultat, error) {
	return func(_ Appelant, p Params) (Resultat, error) {
		return appliquerLien(libelle, param, p, op, "ajouté", "à")
	}
}

func detacher(libelle, param string, op operationLien) func(Appelant, Params) (Resultat, error) {
	return func(_ Appelant, p Params) (Resultat, error) {
		return appliquerLien(libelle, param, p, op, "retiré", "de")
	}
}

func appliquerLien(libelle, param string, p Params, op operationLien, verbe, preposition string) (Resultat, error) {
	groupe := p.Get("group")
	entite := p.Get(param)

	// Le paramètre vide devient une ERREUR et non un silence. C'était le
	// premier des trois défauts : un formulaire soumis sans sélection
	// rechargeait la page à l'identique, sans un mot.
	if groupe == "" {
		return Resultat{}, fmt.Errorf("groupe requis")
	}
	if entite == "" {
		return Resultat{}, fmt.Errorf("%s requis%s", libelle, accord(libelle))
	}

	if err := op(entite, groupe); err != nil {
		// L'erreur de la base est transmise telle quelle. L'ancienne version
		// la remplaçait par une hypothèse — « déjà membre ? » — qui masquait
		// aussi bien un groupe inexistant qu'une base injoignable.
		return Resultat{}, fmt.Errorf("erreur : %s %q, groupe %q : %w", libelle, entite, groupe, err)
	}

	res := Resultat{
		Message: fmt.Sprintf("%s %s %s %s le groupe %s.",
			majuscule(libelle), entite, verbe+accord(libelle), preposition, groupe),
	}
	// Relecture du groupe : plusieurs sections de la page en dépendent, et
	// n'en rafraîchir qu'une afficherait un état partiellement périmé juste
	// après une modification.
	if info, err := dbgroups.Command_GET_GroupInfo(database.GetDatabase(), groupe); err == nil {
		res.Donnees = info
	}
	return res, nil
}

// accord rend « e » pour les libellés féminins.
//
// Détail de langue, mais il touche chaque message que voit l'administrateur.
// « Permission ajouté » se remarque, et donne le sentiment d'un produit
// approximatif — sur une interface d'administration, ce sentiment se reporte
// sur le reste.
func accord(libelle string) string {
	switch {
	case strings.HasPrefix(libelle, "permission"), libelle == "machine", libelle == "GPO":
		return "e"
	default:
		return ""
	}
}

func majuscule(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// --- les opérations, une par ligne ------------------------------------------
//
// Chacune n'existe que pour fixer l'ordre des arguments au bon endroit, une
// seule fois. L'inversion entre ADD et Remove est signalée là où elle se
// produit.

func ajouterUtilisateurAuGroupe(utilisateur, groupe string) error {
	return dbgroups.Command_ADD_UserToGroup(database.GetDatabase(), utilisateur, groupe)
}

func retirerUtilisateurDuGroupe(utilisateur, groupe string) error {
	return dbgroups.Command_Remove_UserFromGroup(database.GetDatabase(), utilisateur, groupe)
}

func ajouterClientAuGroupe(machine, groupe string) error {
	return dbclients.Command_ADD_SoftwareToGroup(database.GetDatabase(), machine, groupe)
}

func retirerClientDuGroupe(machine, groupe string) error {
	return dbclients.Command_Remove_SoftwareFromGroup(database.GetDatabase(), machine, groupe)
}

func ajouterPermissionAuGroupe(permission, groupe string) error {
	// (db, permission, groupe)
	return dbpermission.Command_ADD_UserPermissionToGroup(database.GetDatabase(), permission, groupe)
}

func retirerPermissionDuGroupe(permission, groupe string) error {
	// (db, GROUPE, PERMISSION) — ordre INVERSE de l'ajout ci-dessus.
	return dbpermission.Command_Remove_UserPermissionFromGroup(database.GetDatabase(), groupe, permission)
}

func ajouterPermissionClientAuGroupe(permission, groupe string) error {
	// (db, permission, groupe)
	return dbpermission.Command_ADD_PermissionToSoftwareGroup(database.GetDatabase(), permission, groupe)
}

func retirerPermissionClientDuGroupe(permission, groupe string) error {
	// (db, GROUPE, PERMISSION) — ordre INVERSE de l'ajout ci-dessus.
	return dbpermission.Command_Remove_ClientPermissionFromGroup(database.GetDatabase(), groupe, permission)
}

func lierGPOAuGroupe(gpo, groupe string) error {
	return dbgpo.LinkPolicyToGroup(database.GetDatabase(), gpo, groupe)
}

func delierGPODuGroupe(gpo, groupe string) error {
	return dbgpo.UnlinkPolicyFromGroup(database.GetDatabase(), gpo, groupe)
}

// --- création, suppression, MFA ---------------------------------------------

// creerGroupe corrige un dépassement d'indice de la version en ligne de commande.
//
// L'ancienne version :
//
//	if len(command_list) < 2 {
//	    return "Erreur : -g <nom_du_goupe> <domain>"
//	} else {
//	    dbgroups.CreateGroup(db, command_list[1], command_list[2])
//
// La garde teste `< 2`, le corps lit l'indice 2 — il faut donc au moins TROIS
// éléments. Avec exactement deux, c'est-à-dire `create -g monGroupe` sans
// domaine, l'accès sort du tableau et la goroutine panique.
//
// Ce chemin est atteignable par toute personne autorisée à créer un groupe, et
// une panique dans une goroutine non protégée arrête le processus entier.
func creerGroupe(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("group")
	domaine := p.Get("domain")

	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	if domaine == "" {
		return Resultat{}, fmt.Errorf("domaine requis : un groupe sans domaine ne serait rattaché à rien")
	}
	if strings.ContainsAny(nom, ":\n\r") {
		return Resultat{}, fmt.Errorf("nom de groupe %q invalide : caractères interdits", nom)
	}

	if _, err := dbgroups.CreateGroup(database.GetDatabase(), nom, domaine); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création du groupe : %w", err)
	}

	info, err := dbgroups.Command_GET_GroupInfo(database.GetDatabase(), nom)
	if err != nil {
		// Le groupe est créé ; seule sa relecture échoue. Le signaler comme un
		// échec de création ferait recommencer l'opération, qui échouerait
		// alors pour doublon — et l'administrateur conclurait à un bug.
		return Resultat{Message: fmt.Sprintf("Groupe %s créé dans %s.", nom, domaine)}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("Groupe %s créé dans %s.", nom, domaine),
		Donnees: info,
	}, nil
}

func supprimerGroupe(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("group")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de groupe requis")
	}
	if err := dbgroups.Command_DELETE_GroupWithGroupName(database.GetDatabase(), nom); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression du groupe %q : %w", nom, err)
	}
	return Resultat{Message: fmt.Sprintf("Groupe %s supprimé.", nom)}, nil
}

// reglerMFAGroupe impose ou lève le second facteur pour les membres.
//
// Les membres déjà connectés ne sont pas déconnectés : ils enrôleront à leur
// prochaine connexion. Couper les sessions en cours transformerait un réglage
// de sécurité en incident d'exploitation, et n'apporterait rien — leur mot de
// passe a bien été vérifié, c'est le facteur suivant qu'on ajoute.
//
// Ce commentaire vient de la version web ; la ligne de commande n'exposait pas
// cette action.
func reglerMFAGroupe(a Appelant, p Params) (Resultat, error) {
	groupe := p.Get("group")
	if groupe == "" {
		return Resultat{}, fmt.Errorf("groupe requis")
	}

	// Le web lisait `r.FormValue("mfa_required") == "on"` — la convention des
	// cases à cocher HTML. Ici, on accepte aussi les formes qu'écrirait une
	// ligne de commande, sans quoi l'action serait inutilisable depuis `vlt`.
	requis, err := booleen(p.Get("mfa_required"))
	if err != nil {
		return Resultat{}, err
	}

	if err := dbauthpolicy.SetGroupMFARequired(database.GetDatabase(), groupe, requis, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors du réglage du second facteur : %w", err)
	}

	if requis {
		return Resultat{Message: fmt.Sprintf(
			"Second facteur imposé au groupe %s. Les membres l'enrôleront à leur prochaine connexion.",
			groupe)}, nil
	}
	return Resultat{Message: fmt.Sprintf(
		"Second facteur redevenu facultatif pour le groupe %s.", groupe)}, nil
}

// booleen interprète les formes qu'écrivent un formulaire HTML et un humain.
//
// Une case à cocher non cochée n'est PAS envoyée par le navigateur : le
// paramètre est alors absent, ce qui vaut « faux ». C'est pourquoi la chaîne
// vide est acceptée plutôt que refusée — la refuser rendrait impossible de
// lever le second facteur depuis l'interface, puisque décocher revient à ne
// rien envoyer.
func booleen(v string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "on", "true", "yes", "oui", "1":
		return true, nil
	case "", "off", "false", "no", "non", "0":
		return false, nil
	default:
		return false, fmt.Errorf("valeur %q invalide : attendu oui/non", v)
	}
}
