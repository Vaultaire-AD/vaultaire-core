package webserveur

import (
	"database/sql"
	"strconv"
	"strings"

	dbpermission "vaultaire/core/database/db_permission"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Vue matricielle des permissions RBAC.
//
// Les clés RBAC sont le produit cartésien objet × verbe : les énumérer une par
// une donnait 30 lignes pour 5 objets, et il fallait toutes les parcourir pour
// répondre à « qu'est-ce que cette permission autorise ? ». La matrice met les
// objets en lignes et les verbes en colonnes : ajouter un objet coûte une ligne,
// ajouter un verbe une colonne, et l'ensemble reste lisible d'un coup d'œil.
//
// Rien n'est énuméré en dur ici : les lignes viennent de permission.RBACObjects,
// les colonnes de RBACRead et RBACWrite, les actions hors modèle de
// LegacyActionKeys et SpecialActionKeys. Déclarer un nouvel objet RBAC dans le
// package permission le fait apparaître dans l'interface sans toucher ni à ce
// fichier ni au HTML.

// permissionDomainView est un domaine accordé sur une action.
//
// Le domaine est exposé séparément de sa propagation pour que l'interface
// propose un bouton de retrait par domaine. Auparavant il fallait ressaisir le
// nom du domaine à la main pour le retirer, ce qui invitait à la faute de frappe
// — et une faute de frappe ne retirait rien, silencieusement.
type permissionDomainView struct {
	Name        string
	Propagation string // "0" sans propagation, "1" avec
	Inherited   bool   // vrai si la propagation couvre les sous-domaines
}

// permissionCell est une case de la matrice : une action RBAC et son état.
type permissionCell struct {
	Field   string // clé complète, ex. « write:create:user »
	Value   string // valeur brute en base
	Summary string // résumé court affiché dans la case
	// State pilote la couleur : "nil" (refus), "all" (tous domaines),
	// "custom" (domaines énumérés). Décidé en Go pour que le template n'ait pas
	// à interpréter la syntaxe des valeurs.
	State     string
	Domains   []permissionDomainView
	Available bool // faux si la combinaison objet × verbe n'est pas une clé valide
	// GlobalOnly marque les actions qui ne s'évaluent que sur « * » : l'éditeur
	// n'y propose pas de domaines, parce qu'en ajouter revient à refuser
	// l'action au lieu de la restreindre.
	GlobalOnly bool
}

// permissionMatrixVerb est une colonne de la matrice.
type permissionMatrixVerb struct {
	Key      string // « read:get », « write:create »
	Action   string // « get », « create »
	Category string // « read » ou « write »
	Label    string
}

// permissionMatrixRow est une ligne : un objet et ses cases.
//
// Cells est aligné sur Verbs, index par index, y compris pour les combinaisons
// invalides (case marquée indisponible). Un décalage rendrait la matrice
// mensongère, ce qui est pire qu'un trou visible.
type permissionMatrixRow struct {
	Object     string
	Label      string
	Cells      []permissionCell
	GrantCount int // cases non-nil, pour repérer les objets réellement ouverts
}

// permissionMatrixView est la matrice complète plus les actions hors modèle.
type permissionMatrixView struct {
	Verbs    []permissionMatrixVerb
	Rows     []permissionMatrixRow
	Legacy   []permissionCell
	Special  []permissionCell
	CellByID map[string]permissionCell // accès par clé, pour l'éditeur
}

// rbacObjectLabels traduit les objets en libellés lisibles.
//
// Un objet absent de cette table s'affiche sous son nom technique : une entrée
// manquante dégrade la présentation, elle ne fait pas disparaître la ligne.
var rbacObjectLabels = map[string]string{
	"user":       "Utilisateurs",
	"group":      "Groupes",
	"client":     "Clients",
	"permission": "Permissions",
	"gpo":        "GPO",
}

// rbacVerbLabels traduit les verbes. Même principe de repli que pour les objets.
var rbacVerbLabels = map[string]string{
	"get":    "Consulter",
	"status": "État",
	"create": "Créer",
	"delete": "Supprimer",
	"update": "Modifier",
	"add":    "Rattacher",
}

// labelOr retourne la traduction si elle existe, sinon la clé technique.
func labelOr(table map[string]string, key string) string {
	if label, ok := table[key]; ok {
		return label
	}
	return key
}

// buildPermissionCell analyse une valeur d'action et en fait une case prête à
// rendre.
func buildPermissionCell(field, value string) permissionCell {
	cell := permissionCell{
		Field: field, Value: value, Available: true,
		GlobalOnly: permission.IsGlobalOnlyAction(field),
	}
	parsed := permission.ParsePermissionAction(value)

	switch parsed.Type {
	case "all":
		cell.State = "all"
		cell.Summary = "tous"
		return cell
	case "custom":
		for _, d := range parsed.WithPropagation {
			cell.Domains = append(cell.Domains, permissionDomainView{Name: d, Propagation: "1", Inherited: true})
		}
		for _, d := range parsed.WithoutPropagation {
			cell.Domains = append(cell.Domains, permissionDomainView{Name: d, Propagation: "0"})
		}
	}

	if len(cell.Domains) == 0 {
		// Une valeur « custom » sans aucun domaine accorde en pratique la même
		// chose que nil. L'afficher comme un refus évite de laisser croire à un
		// droit partiel qui n'existe pas.
		cell.State = "nil"
		cell.Summary = "—"
		return cell
	}
	cell.State = "custom"
	if len(cell.Domains) == 1 {
		cell.Summary = "1 dom."
	} else {
		cell.Summary = strconv.Itoa(len(cell.Domains)) + " dom."
	}
	return cell
}

// buildPermissionMatrix lit toutes les actions d'une permission et les range en
// matrice.
func buildPermissionMatrix(db *sql.DB, perm *storage.UserPermission) permissionMatrixView {
	view := permissionMatrixView{CellByID: map[string]permissionCell{}}

	// Colonnes : lectures puis écritures, dans l'ordre déclaré par le package
	// permission. C'est le même ordre que celui des clés générées, donc la
	// matrice et le CLI parlent des mêmes choses dans le même ordre.
	for _, action := range permission.RBACRead {
		view.Verbs = append(view.Verbs, permissionMatrixVerb{
			Key: "read:" + action, Action: action, Category: "read", Label: labelOr(rbacVerbLabels, action),
		})
	}
	for _, action := range permission.RBACWrite {
		view.Verbs = append(view.Verbs, permissionMatrixVerb{
			Key: "write:" + action, Action: action, Category: "write", Label: labelOr(rbacVerbLabels, action),
		})
	}

	read := func(field string) string {
		value, err := dbpermission.Command_GET_UserPermissionAction(db, int64(perm.ID), field)
		if err != nil {
			// Une action absente en base vaut refus : c'est la lecture sûre.
			// Afficher un droit qu'on n'a pas pu lire serait le contraire.
			return "nil"
		}
		return value
	}

	for _, object := range permission.RBACObjects {
		row := permissionMatrixRow{Object: object, Label: labelOr(rbacObjectLabels, object)}
		for _, verb := range view.Verbs {
			field := verb.Category + ":" + verb.Action + ":" + object
			// La combinaison est vérifiée plutôt que supposée : si le modèle
			// venait à ne plus être un produit cartésien plein, la case
			// deviendrait grise au lieu d'exposer une clé que le serveur
			// refuserait à l'écriture.
			if !permission.IsRBACActionKey(field) {
				row.Cells = append(row.Cells, permissionCell{Field: field, Available: false, Summary: "n/a"})
				continue
			}
			cell := buildPermissionCell(field, read(field))
			if cell.State != "nil" {
				row.GrantCount++
			}
			view.CellByID[field] = cell
			row.Cells = append(row.Cells, cell)
		}
		view.Rows = append(view.Rows, row)
	}

	// Actions hors modèle. Les valeurs legacy vivent dans des colonnes dédiées
	// de user_permission et non dans la table des actions, mais la couche base
	// masque déjà cette différence : on lit tout par le même chemin plutôt que
	// de recopier ici une correspondance clé → champ de structure, qui aurait
	// dérivé au premier ajout.
	for _, key := range permission.LegacyActionKeys() {
		cell := buildPermissionCell(key, read(key))
		view.Legacy = append(view.Legacy, cell)
		view.CellByID[key] = cell
	}
	for _, key := range permission.SpecialActionKeys() {
		cell := buildPermissionCell(key, read(key))
		view.Special = append(view.Special, cell)
		view.CellByID[key] = cell
	}

	return view
}

// Deux gardes ont quitté ce fichier.
//
// `permissionFieldExists` — la clé est-elle réellement administrable — et
// `domainGranted` — le domaine à retirer est-il présent — vivaient ici et
// nulle part ailleurs : la ligne de commande n'avait ni l'une ni l'autre.
// C'est ce qui lui permettait d'écrire des clés inventées et d'annoncer le
// retrait de domaines absents.
//
// Elles sont maintenant dans l'action permission.update_action, donc sur le
// chemin des DEUX façades. Les garder ici en double aurait recréé le défaut
// qu'on venait de corriger : deux copies qui divergent.
//
// Voir action.ActionPermissionAdministrable, exportée pour que cette page
// puisse continuer à construire sa matrice sur la même liste que celle qui
// contrôle l'écriture.

// editorCell retourne la case à ouvrir dans l'éditeur, et si elle existe.
func (v permissionMatrixView) editorCell(field string) (permissionCell, bool) {
	cell, ok := v.CellByID[strings.TrimSpace(field)]
	return cell, ok
}
