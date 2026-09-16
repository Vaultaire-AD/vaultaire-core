package webserveur

import (
	"database/sql"
	"net/http"
	"sort"
	"strings"
	dbgroups "vaultaire/core/database/db_groups"
	isprotected "vaultaire/core/database/is_protected"

	act "vaultaire/core/action"
	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
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

// collectModuleParams et checkGPORBAC ont quitté ce fichier.
//
// La première extrayait les paramètres d'un module d'après le catalogue ; la
// seconde décidait des droits sur les domaines couverts par une GPO. Toutes
// deux vivaient ICI et nulle part ailleurs : la ligne de commande créait et
// supprimait des GPO sans le raisonnement de la seconde, et n'avait jamais eu
// besoin de la première.
//
// Elles sont maintenant dans core/action — action.ParametresDeModule et la
// portée porteeGPO — donc sur le chemin des deux façades. Le raisonnement de
// checkGPORBAC est conservé mot pour mot dans l'en-tête de actions_gpo.go :
// une GPO couvre les domaines des groupes auxquels elle est liée et s'applique
// à tous à la fois, donc la modifier exige le droit sur chacun.

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
		IsSuperadmin:  isprotected.IsSuperadmin(db, username),
		SuperadminGrp: isprotected.ProtectedGroupName,
	}

	if r.Method == http.MethodPost {
		// Création et suppression passent par le registre.
		//
		// Le contrôle de droits, la validation de la portée et la vérification
		// après suppression vivent dans les actions gpo.create et gpo.delete —
		// donc partagés avec la ligne de commande, qui n'avait ni la seconde
		// ni la troisième.
		res, traite, errAction := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if errAction != nil {
				data.Error = MessageDActionPourAffichage(res, errAction)
			} else {
				data.Message = res.Message
			}
		}
	}

	// La liste passe par gpo.list : elle est réduite au périmètre de
	// l'appelant, comme les autres listes de l'interface.
	resListe, err := ExecuterLecture("gpo.list", username, groupIDs, act.Params{})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: list gpo failed: "+err.Error())
		http.Error(w, "Erreur liste GPO", http.StatusInternalServerError)
		return
	}
	data.Policies, _ = resListe.Donnees.([]dbgpo.PolicySummary)

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
		// L'onglet d'origine est transporté par le formulaire pour être rouvert
		// après l'action. Sans lui, chaque ajout de module ramènerait sur le
		// premier onglet et il faudrait re-naviguer à chaque fois.
		data.ActiveTab = sanitizeTab(r.FormValue("active_tab"))

		// Les sept actions de cette page passent par le registre.
		//
		// La table « action → clé RBAC » et le `if actionKey != ""` qui la
		// suivait ont disparu : ce motif sautait la vérification pour toute
		// action absente de la table, et c'est exactement le fail-open corrigé
		// partout ailleurs.
		//
		// Ce qui a suivi le déménagement, et qui n'existait QUE côté web :
		// la validation des paramètres de module contre le catalogue, et le
		// contrôle que le module visé appartient bien à la GPO affichée — sans
		// quoi un identifiant forgé modifie le module d'une autre GPO, dont on
		// n'a pas les droits.
		//
		// Ce qui a changé de portée : lier ou délier un groupe exige désormais
		// le droit sur l'union des domaines du groupe ET de la GPO. Voir
		// action.PorteeGPOEtGroupe.
		//
		// Le nom de la GPO vient de l'URL : les formulaires ne le répètent pas.
		res, traite, errAction := ExecuterActionFormulaireAvec(r, username, groupIDs,
			act.Params{"gpo": gpoName})

		if traite {
			if errAction != nil {
				data.Error = MessageDActionPourAffichage(res, errAction)
			} else {
				data.Message = res.Message

				// La suppression renvoie vers la liste : la fiche d'une GPO
				// supprimée serait vide.
				if r.FormValue("action") == "delete_gpo" {
					http.Redirect(w, r, "/admin/gpo", http.StatusSeeOther)
					return
				}
			}
		}

		// Rechargement après action : l'affichage doit refléter l'état réel en
		// base, pas l'état supposé après l'écriture.
		//
		// Relu ici plutôt que pris dans res.Donnees : la plupart de ces actions
		// portent sur les MODULES et rendent un compte rendu, pas la politique
		// entière. Une relecture unique couvre les sept cas.
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

	if allDetails, groupErr := dbgroups.Command_GET_GroupDetails(db); groupErr == nil {
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
