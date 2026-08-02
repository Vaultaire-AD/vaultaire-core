package webserveur

import (
	"net/http"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Page d'édition des restrictions GPO — /admin/gpo/restrictions.
//
// Accès réservé aux membres du groupe superadmin `vaultaire`. Ce n'est pas une
// clé RBAC parmi d'autres : ces réglages déterminent ce que l'ensemble du parc
// accepte d'appliquer, donc ils sont au-dessus de la délégation par domaine.
// La couche base revérifie l'appartenance à chaque écriture (voir
// db_gpo/restrictions.go) ; le contrôle ici sert à ne pas afficher une interface
// dont aucun bouton ne fonctionnerait.

// restrictionFieldView est un champ à domaine dynamique, avec sa règle et ses
// valeurs, prêt à rendre.
type restrictionFieldView struct {
	ModuleType  string
	ModuleLabel string
	FieldName   string
	Label       string
	Help        string
	Key         string
	Mode        string
	ModeLabel   string
	AllowPatt   string
	DenyPatt    string
	UpdatedBy   string
	Values      []dbgpo.RestrictionRow
	IsList      bool
	IsPattern   bool
	IsFree      bool

	// Champs à contenu : le domaine du champ est une liste de définitions
	// nommées portant chacune un contenu, et non de simples noms.
	HasPayload         bool
	PayloadLabel       string
	PayloadHelp        string
	PayloadPlaceholder string
	PayloadMultiline   bool
	Definitions        []dbgpo.DefinitionRow

	// SearchText concatène en minuscules ce sur quoi porte le filtre de la page.
	// Calculé ici plutôt que dans le navigateur : le texte de recherche d'un
	// champ ne change pas d'une frappe à l'autre.
	SearchText string
}

// modeLabel traduit un mode de champ en explication courte.
func modeLabel(mode string) string {
	switch mode {
	case gpo.FieldModePattern:
		return "motif — toute valeur conforme à l'expression régulière est acceptée"
	case gpo.FieldModeFree:
		return "libre — aucune contrainte de domaine, seul le motif d'exclusion s'applique"
	default:
		return "liste — seules les valeurs énumérées sont acceptées"
	}
}

// requireSuperadminPage vérifie la session, le droit web_admin, puis
// l'appartenance au groupe superadmin.
func requireSuperadminPage(w http.ResponseWriter, r *http.Request) (string, bool) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return "", false
	}
	if !database.IsSuperadmin(database.GetDatabase(), username) {
		logs.Write_Log("SECURITY", "webadmin: "+username+" a tenté d'accéder aux restrictions GPO sans être membre du groupe "+database.ProtectedGroupName)
		http.Error(w, "Réservé aux membres du groupe "+database.ProtectedGroupName, http.StatusForbidden)
		return "", false
	}
	return username, true
}

// AdminGPORestrictionsHandler affiche et édite les restrictions GPO.
func AdminGPORestrictionsHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireSuperadminPage(w, r)
	if !ok {
		return
	}
	db := database.GetDatabase()

	data := struct {
		Username      string
		DnsEnable     bool
		Section       string
		Message       string
		Error         string
		LoadError     string
		Fields        []restrictionFieldView
		PathDeny      []dbgpo.RestrictionRow
		PathAllow     []dbgpo.RestrictionRow
		EnvDeny       []dbgpo.RestrictionRow
		Modes         []string
		PathScopes    []string
		HomeMarker    string
		SuperadminGrp string
		FieldCount    int
		PathCount     int
		EnvCount      int
		// ActiveTab est l'onglet rouvert après une action : sans lui, ajouter un
		// chemin refusé renverrait sur la liste des champs à chaque fois.
		ActiveTab string
	}{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "gpo",
		Modes:      gpo.AllFieldModes(),
		PathScopes: []string{gpo.PathScopeAny, string(gpo.ScopeMachine), string(gpo.ScopeUser)},
		HomeMarker: gpo.UserHomePlaceholder(), SuperadminGrp: database.ProtectedGroupName,
	}

	if r.Method == http.MethodPost {
		data.ActiveTab = sanitizeTabFrom(r.FormValue("active_tab"), gpoRestrictionTabs)
		switch r.FormValue("action") {
		case "add_value":
			err := dbgpo.AddAllowedValue(db, username,
				r.FormValue("module_type"), r.FormValue("field_name"),
				r.FormValue("value"), r.FormValue("label"))
			setRestrictionOutcome(&data.Message, &data.Error, err, "Valeur ajoutée.")

		case "set_rule":
			err := dbgpo.SetFieldRule(db, username,
				r.FormValue("module_type"), r.FormValue("field_name"),
				r.FormValue("mode"), r.FormValue("allow_pattern"), r.FormValue("deny_pattern"))
			setRestrictionOutcome(&data.Message, &data.Error, err, "Règle du champ enregistrée.")

		case "add_path":
			err := dbgpo.AddPathRule(db, username,
				r.FormValue("scope"), r.FormValue("rule_type") == "deny",
				r.FormValue("prefix"), r.FormValue("note"))
			setRestrictionOutcome(&data.Message, &data.Error, err, "Règle de chemin ajoutée.")

		case "add_env":
			err := dbgpo.AddEnvDeny(db, username, r.FormValue("env_name"), r.FormValue("note"))
			setRestrictionOutcome(&data.Message, &data.Error, err, "Variable interdite ajoutée.")

		case "save_definition":
			err := dbgpo.SaveDefinition(db, username,
				r.FormValue("module_type"), r.FormValue("field_name"),
				r.FormValue("name"), r.FormValue("payload"), r.FormValue("note"))
			setRestrictionOutcome(&data.Message, &data.Error, err, "Définition enregistrée.")

		case "delete_definition":
			id, convErr := strconv.Atoi(r.FormValue("definition_id"))
			if convErr != nil {
				data.Error = "Identifiant invalide."
				break
			}
			err := dbgpo.DeleteDefinition(db, username, id)
			setRestrictionOutcome(&data.Message, &data.Error, err, "Définition supprimée.")

		case "delete_restriction":
			id, convErr := strconv.Atoi(r.FormValue("restriction_id"))
			if convErr != nil {
				data.Error = "Identifiant invalide."
				break
			}
			err := dbgpo.DeleteRestriction(db, username, id)
			setRestrictionOutcome(&data.Message, &data.Error, err, "Restriction supprimée.")

		case "reset_defaults":
			if r.FormValue("confirm") != "RESET" {
				data.Error = "Saisissez RESET pour confirmer la réinitialisation."
				break
			}
			err := dbgpo.ResetRestrictionsToDefaults(db, username)
			setRestrictionOutcome(&data.Message, &data.Error, err,
				"Restrictions réinitialisées au socle par défaut.")
		}
	}

	// Chargement de l'état courant après action, pour refléter la base et non
	// l'état supposé.
	for _, f := range gpo.DynamicFields() {
		rule, err := dbgpo.GetFieldRule(db, f.ModuleType, f.FieldName)
		if err != nil {
			data.Error = appendError(data.Error, err.Error())
			continue
		}
		view := restrictionFieldView{
			ModuleType: f.ModuleType, ModuleLabel: gpo.ModuleLabel(f.ModuleType),
			FieldName: f.FieldName, Label: f.Label, Help: f.Help, Key: f.Key(),
			Mode: rule.Mode, ModeLabel: modeLabel(rule.Mode),
			AllowPatt: rule.AllowPattern, DenyPatt: rule.DenyPattern, UpdatedBy: rule.UpdatedBy,
			IsList:     rule.Mode == gpo.FieldModeList || rule.Mode == "",
			IsPattern:  rule.Mode == gpo.FieldModePattern,
			IsFree:     rule.Mode == gpo.FieldModeFree,
			HasPayload: f.HasPayload(),
		}

		// Un champ à contenu et un champ à liste simple ne se gèrent pas de la
		// même façon : le premier édite des définitions (nom + contenu), le
		// second une simple liste de valeurs. On ne charge que ce qui sert.
		if view.HasPayload {
			if desc, ok := gpo.PayloadDescriptorFor(f.PayloadKind); ok {
				view.PayloadLabel = desc.Label
				view.PayloadHelp = desc.Help
				view.PayloadPlaceholder = desc.Placeholder
				view.PayloadMultiline = desc.Multiline
			}
			defs, err := dbgpo.ListDefinitionsForField(db, f.ModuleType, f.FieldName)
			if err != nil {
				data.Error = appendError(data.Error, err.Error())
			}
			view.Definitions = defs
		} else {
			values, err := dbgpo.ListAllowedValuesForField(db, f.ModuleType, f.FieldName)
			if err != nil {
				data.Error = appendError(data.Error, err.Error())
			}
			view.Values = values
		}

		// Le filtre porte sur le libellé du champ, celui du module, la clé
		// technique et le mode : on cherche un champ soit par son nom métier,
		// soit par sa clé, soit pour voir tout ce qui est encore en mode libre.
		view.SearchText = strings.ToLower(strings.Join(
			[]string{view.Label, view.ModuleLabel, view.ModuleType, view.FieldName, view.Key, view.Mode}, " "))

		data.Fields = append(data.Fields, view)
	}

	var err error
	if data.PathDeny, err = dbgpo.ListRestrictionsByKind(db, dbgpo.KindPathDeny); err != nil {
		data.Error = appendError(data.Error, err.Error())
	}
	if data.PathAllow, err = dbgpo.ListRestrictionsByKind(db, dbgpo.KindPathAllow); err != nil {
		data.Error = appendError(data.Error, err.Error())
	}
	if data.EnvDeny, err = dbgpo.ListRestrictionsByKind(db, dbgpo.KindEnvDeny); err != nil {
		data.Error = appendError(data.Error, err.Error())
	}
	data.LoadError = gpo.LastRestrictionError()
	data.FieldCount = len(data.Fields)
	data.PathCount = len(data.PathDeny) + len(data.PathAllow)
	data.EnvCount = len(data.EnvDeny)
	if data.ActiveTab == "" {
		data.ActiveTab = "fields"
	}

	if err := executeAdminPage(w, "admin_gpo_restrictions.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template admin_gpo_restrictions.html: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// setRestrictionOutcome place le message de succès ou l'erreur.
func setRestrictionOutcome(message, errMsg *string, err error, success string) {
	if err != nil {
		*errMsg = err.Error()
		return
	}
	*message = success
}

// appendError concatène des erreurs de chargement pour n'en perdre aucune.
func appendError(existing, addition string) string {
	if strings.TrimSpace(existing) == "" {
		return addition
	}
	return existing + " · " + addition
}
