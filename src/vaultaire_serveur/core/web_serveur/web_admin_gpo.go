package webserveur

import (
	"database/sql"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

// Page d'administration des GPO.
//
// Elle est entièrement pilotée par le catalogue de core/gpo : les formulaires
// sont générés depuis les schémas de modules, donc l'interface ne peut pas
// proposer un champ ou une valeur que le serveur refuserait. Ajouter un module
// au catalogue le rend éditable ici sans toucher au HTML.
//
// RBAC : mêmes clés que les commandes CLI (read:get:gpo, write:create:gpo,
// write:update:gpo, write:add:gpo, write:delete:gpo), vérifiées sur les domaines
// des groupes auxquels la GPO est liée.

// gpoFieldView est un champ de formulaire prêt à rendre.
// Les booléens IsEnum/IsBool/… évitent des comparaisons de chaînes dans le
// template : le choix du widget est décidé en Go, une seule fois.
type gpoFieldView struct {
	Name     string
	Label    string
	Help     string
	Value    string
	Required bool
	Options  []string
	Min      int
	Max      int
	HasRange bool
	IsEnum   bool
	IsBool   bool
	IsText   bool
	IsInt    bool
	IsPath   bool
	// Definitions expose le contenu des valeurs nommées, pour que l'administrateur
	// voie ce qu'un choix accorde réellement. Choisir un jeu de commandes sudo
	// sans en voir la liste serait une décision prise à l'aveugle.
	Definitions []gpoDefinitionView
}

// gpoDefinitionView est le contenu d'une valeur nommée, affiché en lecture seule.
type gpoDefinitionView struct {
	Name    string
	Note    string
	Lines   []string
	Current bool
}

// gpoModuleView est un module existant, avec ses champs valorisés.
type gpoModuleView struct {
	ID          int
	Type        string
	Label       string
	Category    string
	Description string
	ApplyOrder  int
	Fields      []gpoFieldView
	Summary     string
	// Target est la cible du module — la clé qui le distingue des autres du
	// même type (une clé sysctl, un nom de service, un chemin). Affichée en
	// colonne dédiée : c'est l'information qu'on cherche en parcourant une liste,
	// bien avant le détail des paramètres.
	Target string
	// SearchText concatène ce sur quoi le filtre porte, en minuscules, pour que
	// le script n'ait pas à reconstruire la chaîne à chaque frappe.
	SearchText string
}

// gpoCatalogEntry est une entrée du catalogue proposée à l'ajout.
type gpoCatalogEntry struct {
	Type        string
	Label       string
	Category    string
	Description string
	Fields      []gpoFieldView
	SearchText  string
}

// gpoCatalogCategory regroupe les entrées du catalogue par catégorie.
type gpoCatalogCategory struct {
	Name    string
	Entries []gpoCatalogEntry
}

// buildFieldViews convertit les champs d'un schéma en vues de formulaire,
// valorisées par params (nil pour un formulaire d'ajout : les valeurs par défaut
// du schéma s'appliquent alors).
func buildFieldViews(schema gpo.ModuleSchema, params map[string]string) []gpoFieldView {
	views := make([]gpoFieldView, 0, len(schema.Fields))
	for _, f := range schema.Fields {
		value := f.Default
		if params != nil {
			if v, ok := params[f.Name]; ok {
				value = v
			}
		}
		view := gpoFieldView{
			Name:     f.Name,
			Label:    f.Label,
			Help:     f.Help,
			Value:    value,
			Required: f.Required,
			Options:  f.Options,
			Min:      f.Min,
			Max:      f.Max,
			HasRange: !(f.Min == 0 && f.Max == 0),
			IsEnum:   f.Type == gpo.FieldEnum,
			IsBool:   f.Type == gpo.FieldBool,
			IsText:   f.Type == gpo.FieldText,
			IsInt:    f.Type == gpo.FieldInt,
			IsPath:   f.Type == gpo.FieldPath,
		}

		if gpo.FieldHasPayload(schema.Type, f.Name) {
			for _, d := range gpo.Restrictions().DefinitionsFor(schema.Type, f.Name) {
				view.Definitions = append(view.Definitions, gpoDefinitionView{
					Name: d.Name, Note: d.Note, Lines: d.Lines(), Current: d.Name == value,
				})
			}
		}

		views = append(views, view)
	}
	return views
}

// buildModuleViews convertit les modules d'une GPO en vues éditables.
func buildModuleViews(modules []gpo.Module) []gpoModuleView {
	views := make([]gpoModuleView, 0, len(modules))
	for _, m := range modules {
		schema, known := gpo.SchemaFor(m.Type)
		view := gpoModuleView{
			ID:         m.ID,
			Type:       m.Type,
			Label:      m.Type,
			ApplyOrder: m.ApplyOrder,
			Summary:    moduleSummary(m),
			Target:     moduleTarget(m),
		}
		if known {
			view.Label = schema.Label
			view.Category = schema.Category
			view.Description = schema.Description
			view.Fields = buildFieldViews(schema, m.Params)
		}
		view.SearchText = strings.ToLower(strings.Join(
			[]string{view.Label, view.Type, view.Target, view.Summary, view.Category}, " "))
		views = append(views, view)
	}
	return views
}

// moduleTarget extrait la cible d'un module : ce qui le distingue des autres du
// même type.
//
// Dérivée de la clé d'état côté serveur (« sysctl:net.ipv4.ip_forward »), dont
// on ne garde que la partie après le préfixe de type. Recalculer la logique ici
// la ferait diverger de celle qui sert réellement au suivi des modules.
func moduleTarget(m gpo.Module) string {
	key := gpo.ModuleStateKey(m)
	if idx := strings.Index(key, ":"); idx >= 0 {
		target := key[idx+1:]
		if target == "-" {
			// Module unique par politique (SSH serveur) : pas de cible à afficher.
			return ""
		}
		return target
	}
	return ""
}

// moduleSummary produit une ligne de résumé lisible d'un module, pour que la
// liste reste compréhensible sans déplier chaque formulaire.
//
// La cible est volontairement exclue : elle a sa propre colonne dans le tableau,
// la répéter dans le résumé mangerait la place des autres paramètres.
func moduleSummary(m gpo.Module) string {
	schema, known := gpo.SchemaFor(m.Type)
	if !known {
		return ""
	}
	target := moduleTarget(m)

	var parts []string
	for _, f := range schema.Fields {
		val := strings.TrimSpace(m.Params[f.Name])
		if val == "" || val == "unchanged" || strings.Contains(val, "\n") {
			continue
		}
		if val == target {
			continue
		}
		parts = append(parts, f.Label+" = "+val)
		if len(parts) == 4 {
			break
		}
	}
	return strings.Join(parts, " · ")
}

// buildCatalogForScope construit le catalogue proposé à l'ajout, groupé par
// catégorie et limité aux modules autorisés dans ce scope.
func buildCatalogForScope(scope gpo.Scope) []gpoCatalogCategory {
	byCategory := map[string][]gpoCatalogEntry{}
	for _, schema := range gpo.CatalogForScope(scope) {
		byCategory[schema.Category] = append(byCategory[schema.Category], gpoCatalogEntry{
			Type:        schema.Type,
			Label:       schema.Label,
			Category:    schema.Category,
			Description: schema.Description,
			Fields:      buildFieldViews(schema, nil),
			SearchText: strings.ToLower(strings.Join(
				[]string{schema.Label, schema.Type, schema.Category, schema.Description}, " ")),
		})
	}
	var out []gpoCatalogCategory
	for _, name := range gpo.CategoriesForScope(scope) {
		out = append(out, gpoCatalogCategory{Name: name, Entries: byCategory[name]})
	}
	return out
}

// collectModuleParams extrait les paramètres d'un module depuis le formulaire.
//
// Seuls les champs déclarés au schéma sont lus : un champ injecté dans la requête
// HTTP n'est pas ignoré silencieusement, il n'est simplement jamais consulté.
// Les cases à cocher absentes de la requête valent "false" (une case décochée
// n'est pas transmise par le navigateur).
func collectModuleParams(r *http.Request, moduleType string) map[string]string {
	schema, ok := gpo.SchemaFor(moduleType)
	if !ok {
		return nil
	}
	params := make(map[string]string, len(schema.Fields))
	for _, f := range schema.Fields {
		raw := r.FormValue("p_" + f.Name)
		if f.Type == gpo.FieldBool {
			if raw == "on" || raw == "true" || raw == "1" {
				params[f.Name] = "true"
			} else {
				params[f.Name] = "false"
			}
			continue
		}
		params[f.Name] = raw
	}
	return params
}

// checkGPORBAC vérifie une action RBAC sur les domaines couverts par une GPO.
//
// Contrairement à un contrôle sur "*", cela permet de déléguer la gestion des
// GPO d'un domaine sans donner la main sur tout l'annuaire. Une GPO sans groupe
// ne couvre aucun domaine : on exige alors le droit global, sinon une GPO en
// attente de rattachement serait modifiable par n'importe quel délégué.
func checkGPORBAC(groupIDs []int, actionKey, gpoName string) (bool, string) {
	domains := []string{"*"}
	if gpoName != "" {
		if d, err := permission.GetDomainslistFromGPO(gpoName); err == nil && len(d) > 0 {
			domains = d
		}
	}
	return permission.CheckPermissionsMultipleDomains(groupIDs, actionKey, domains)
}

// AdminGPOHandler liste les GPO ou affiche le détail quand ?gpo= est présent.
// Accès : web_admin + read:get:gpo pour consulter ; write:create|update|add|delete:gpo
// pour les actions POST, exactement comme le package commande.
func AdminGPOHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:gpo") {
		return
	}
	db := database.GetDatabase()

	if detailGPO := r.URL.Query().Get("gpo"); detailGPO != "" {
		adminGPODetail(w, r, db, username, groupIDs, detailGPO)
		return
	}
	adminGPOList(w, r, db, username, groupIDs)
}

// adminGPOList gère la vue liste : création et suppression de GPO.
func adminGPOList(w http.ResponseWriter, r *http.Request, db *sql.DB, username string, groupIDs []int) {
	data := struct {
		Policies      []dbgpo.PolicySummary
		Scopes        []gpo.Scope
		Message       string
		Error         string
		Username      string
		DnsEnable     bool
		Section       string
		IsSuperadmin  bool
		SuperadminGrp string
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "gpo", Scopes: gpo.AllScopes(),
		IsSuperadmin:  database.IsSuperadmin(db, username),
		SuperadminGrp: database.ProtectedGroupName,
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		switch action {
		case "create_gpo":
			if allowed, reason := checkGPORBAC(groupIDs, "write:create:gpo", ""); !allowed {
				data.Error = "Permission refusée : " + reason
				break
			}
			name := strings.TrimSpace(r.FormValue("gpo_name"))
			scope := gpo.Scope(r.FormValue("scope"))
			description := r.FormValue("description")
			if !gpo.IsValidPolicyScope(scope) {
				data.Error = "Scope invalide : une GPO est soit machine, soit user."
				break
			}
			if _, err := dbgpo.CreatePolicy(db, name, scope, description); err != nil {
				data.Error = "Erreur création : " + err.Error()
				logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: create gpo failed: "+err.Error())
			} else {
				data.Message = "GPO créée. Ajoutez-y des modules depuis son détail."
				logs.Write_Log("INFO", "webadmin: GPO "+name+" créée par "+username)
			}

		case "delete_gpo":
			name := strings.TrimSpace(r.FormValue("gpo_name"))
			if allowed, reason := checkGPORBAC(groupIDs, "write:delete:gpo", name); !allowed {
				data.Error = "Permission refusée : " + reason
				break
			}
			if err := dbgpo.DeletePolicyByName(db, name); err != nil {
				data.Error = "Erreur suppression : " + err.Error()
			} else {
				data.Message = "GPO supprimée."
				logs.Write_Log("INFO", "webadmin: GPO "+name+" supprimée par "+username)
			}
		}
	}

	policies, err := dbgpo.GetAllPolicies(db)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list gpo failed: "+err.Error())
		http.Error(w, "Erreur liste GPO", http.StatusInternalServerError)
		return
	}
	data.Policies = policies

	if err := executeAdminPage(w, "admin_gpo.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template admin_gpo.html: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// adminGPODetail gère la vue détail : métadonnées, modules, liaisons de groupe.
func adminGPODetail(w http.ResponseWriter, r *http.Request, db *sql.DB, username string, groupIDs []int, gpoName string) {
	policy, err := dbgpo.GetPolicyByName(db, gpoName)
	if err != nil {
		http.Error(w, "GPO introuvable", http.StatusNotFound)
		return
	}

	data := struct {
		Policy     *gpo.Policy
		ScopeLabel string
		Modules    []gpoModuleView
		Catalog    []gpoCatalogCategory
		// CatalogFlat est le catalogue à plat, trié par libellé : c'est sur lui
		// que porte la recherche. Le regroupement par catégorie reste disponible
		// dans Catalog pour l'affichage sans JavaScript.
		CatalogFlat  []gpoCatalogEntry
		AllGroups    []string
		Hash         string
		Message      string
		Error        string
		Username     string
		DnsEnable    bool
		Section      string
		HomeMarker   string
		MachineOnly  []string
		ModuleCount  int
		GroupCount   int
		CatalogCount int
		// ActiveTab est l'onglet à ouvrir au chargement. Après une action, on
		// revient sur l'onglet d'où elle a été lancée : sans cela, ajouter un
		// module renverrait l'administrateur sur le premier onglet à chaque fois.
		ActiveTab string
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "gpo",
		HomeMarker: gpo.UserHomePlaceholder(), MachineOnly: gpo.MachineOnlyModuleTypes(),
	}

	if r.Method == http.MethodPost {
		action := r.FormValue("action")

		// L'onglet d'origine est transporté par le formulaire pour être rouvert
		// après l'action. Sans lui, chaque ajout de module ramènerait sur le
		// premier onglet et il faudrait re-naviguer à chaque fois.
		data.ActiveTab = sanitizeTab(r.FormValue("active_tab"))

		// Toutes les actions de cette page portent sur une GPO existante :
		// une seule vérification de permission, sur la clé propre à l'action.
		actionKey := ""
		switch action {
		case "update_gpo", "add_module", "update_module", "delete_module":
			actionKey = "write:update:gpo"
		case "link_group":
			actionKey = "write:add:gpo"
		case "unlink_group", "delete_gpo":
			actionKey = "write:delete:gpo"
		}
		if actionKey != "" {
			if allowed, reason := checkGPORBAC(groupIDs, actionKey, gpoName); !allowed {
				logs.Write_Log("SECURITY", "webadmin: "+username+" tente "+action+" sur la GPO "+gpoName+" — "+reason)
				data.Error = "Permission refusée : " + reason
				action = ""
			}
		}

		switch action {
		case "update_gpo":
			description := r.FormValue("description")
			enabled := r.FormValue("enabled") == "on"
			if err := dbgpo.UpdatePolicyMeta(db, policy.ID, description, enabled); err != nil {
				data.Error = "Erreur : " + err.Error()
			} else {
				data.Message = "GPO mise à jour."
			}

		case "add_module":
			moduleType := r.FormValue("module_type")
			params := collectModuleParams(r, moduleType)
			if params == nil {
				data.Error = "Type de module inconnu."
				break
			}
			if _, err := dbgpo.AddModule(db, policy.ID, moduleType, params); err != nil {
				data.Error = "Module refusé : " + err.Error()
			} else {
				data.Message = "Module ajouté."
			}

		case "update_module":
			moduleID, convErr := strconv.Atoi(r.FormValue("module_id"))
			if convErr != nil {
				data.Error = "Identifiant de module invalide."
				break
			}
			existing, owner, getErr := dbgpo.GetModuleByID(db, moduleID)
			if getErr != nil {
				data.Error = getErr.Error()
				break
			}
			// Le module doit appartenir à la GPO affichée : sans ce contrôle,
			// un identifiant forgé permettrait de modifier le module d'une autre
			// GPO, dont l'utilisateur n'a pas forcément les droits sur le domaine.
			if owner != policy.ID {
				logs.Write_Log("SECURITY", "webadmin: "+username+" tente de modifier le module "+strconv.Itoa(moduleID)+" hors de la GPO "+gpoName)
				data.Error = "Ce module n'appartient pas à cette GPO."
				break
			}
			params := collectModuleParams(r, existing.Type)
			if err := dbgpo.UpdateModuleParams(db, moduleID, params); err != nil {
				data.Error = "Module refusé : " + err.Error()
			} else {
				data.Message = "Module mis à jour."
			}

		case "delete_module":
			moduleID, convErr := strconv.Atoi(r.FormValue("module_id"))
			if convErr != nil {
				data.Error = "Identifiant de module invalide."
				break
			}
			_, owner, getErr := dbgpo.GetModuleByID(db, moduleID)
			if getErr != nil {
				data.Error = getErr.Error()
				break
			}
			if owner != policy.ID {
				logs.Write_Log("SECURITY", "webadmin: "+username+" tente de supprimer le module "+strconv.Itoa(moduleID)+" hors de la GPO "+gpoName)
				data.Error = "Ce module n'appartient pas à cette GPO."
				break
			}
			if err := dbgpo.DeleteModule(db, moduleID); err != nil {
				data.Error = "Erreur : " + err.Error()
			} else {
				data.Message = "Module retiré."
			}

		case "link_group":
			groupName := strings.TrimSpace(r.FormValue("group"))
			if groupName == "" {
				data.Error = "Groupe requis."
				break
			}
			if err := dbgpo.LinkPolicyToGroup(db, gpoName, groupName); err != nil {
				data.Error = err.Error()
			} else {
				data.Message = "GPO liée au groupe " + groupName + "."
			}

		case "unlink_group":
			groupName := strings.TrimSpace(r.FormValue("group"))
			if err := dbgpo.UnlinkPolicyFromGroup(db, gpoName, groupName); err != nil {
				data.Error = err.Error()
			} else {
				data.Message = "GPO retirée du groupe " + groupName + "."
			}

		case "delete_gpo":
			if err := dbgpo.DeletePolicyByName(db, gpoName); err != nil {
				data.Error = "Erreur suppression : " + err.Error()
			} else {
				http.Redirect(w, r, "/admin/gpo", http.StatusSeeOther)
				return
			}
		}

		// Rechargement après action : l'affichage doit refléter l'état réel en
		// base, pas l'état supposé après l'écriture.
		if reloaded, reloadErr := dbgpo.GetPolicyByName(db, gpoName); reloadErr == nil {
			policy = reloaded
		}
	}

	data.Policy = policy
	data.Modules = buildModuleViews(policy.Modules)
	data.Catalog = buildCatalogForScope(policy.Scope)
	data.CatalogFlat = flattenCatalog(data.Catalog)
	data.ModuleCount = len(data.Modules)
	data.GroupCount = len(policy.Groups)
	data.CatalogCount = len(data.CatalogFlat)
	if data.ActiveTab == "" {
		data.ActiveTab = "modules"
	}
	if hash, hashErr := gpo.PolicyHash(*policy); hashErr == nil {
		data.Hash = hash
	}
	switch policy.Scope {
	case gpo.ScopeMachine:
		data.ScopeLabel = "Machine — appliquée à l'ordinateur au démarrage puis par rafraîchissement périodique, indépendamment de l'utilisateur connecté."
	case gpo.ScopeUser:
		data.ScopeLabel = "Utilisateur — appliquée après une authentification réussie, à l'utilisateur authentifié. Les modules touchant aux privilèges (SSH, sudo, sysctl, paquets, services) ne sont pas disponibles dans ce scope."
	}

	if allDetails, groupErr := database.Command_GET_GroupDetails(db); groupErr == nil {
		linked := map[string]bool{}
		for _, g := range policy.Groups {
			linked[g] = true
		}
		for _, g := range allDetails {
			if !linked[g.GroupName] {
				data.AllGroups = append(data.AllGroups, g.GroupName)
			}
		}
	}

	if err := executeAdminPage(w, "admin_gpo_detail.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template admin_gpo_detail.html: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// flattenCatalog aplatit le catalogue et le trie par libellé.
//
// La recherche porte sur cette liste : filtrer une liste plate est immédiat,
// alors que filtrer une structure groupée obligerait à masquer aussi les
// catégories devenues vides, puis à les faire réapparaître quand le filtre
// change.
func flattenCatalog(categories []gpoCatalogCategory) []gpoCatalogEntry {
	var out []gpoCatalogEntry
	for _, c := range categories {
		out = append(out, c.Entries...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Label < out[j].Label })
	return out
}

// gpoTabs liste les onglets de la page de détail.
//
// La liste est en dur côté serveur plutôt que déduite du formulaire : une valeur
// forgée dans active_tab se retrouverait sinon telle quelle dans un attribut
// HTML, et désignerait un onglet qui n'existe pas.
var gpoTabs = []string{"modules", "add", "groups", "settings"}

// gpoRestrictionTabs liste les onglets de la page des restrictions.
var gpoRestrictionTabs = []string{"fields", "paths", "env", "reset"}

// sanitizeTab ne retient qu'un identifiant d'onglet connu.
func sanitizeTab(raw string) string { return sanitizeTabFrom(raw, gpoTabs) }

// sanitizeTabFrom ne retient qu'un identifiant appartenant à la liste fournie.
func sanitizeTabFrom(raw string, allowed []string) string {
	value := strings.TrimSpace(raw)
	for _, tab := range allowed {
		if tab == value {
			return value
		}
	}
	return ""
}
