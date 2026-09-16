package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Validation des GPO.
//
// Deux propriétés sont garanties ici :
//  1. Aucun champ hors schéma n'est accepté (pas seulement : les champs du
//     schéma sont vérifiés). Un paramètre inconnu est une erreur, pas un champ
//     ignoré — sinon on pourrait faire transiter des données vers un agent
//     client plus permissif.
//  2. Toute valeur est vérifiée contre son type ET contre les garde-fous de
//     guards.go, avant écriture en base. La validation n'est pas seulement
//     rejouée à l'application côté client : elle bloque l'entrée.

var (
	policyNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$`)
	identRe      = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	envNameRe    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	modeRe       = regexp.MustCompile(`^0?[0-7]{3}$`)
	cronFieldRe  = regexp.MustCompile(`^(\*|[0-9]+)([-/,][0-9]+)*(/[0-9]+)?$`)

	packageVersionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:+~-]{0,63}$`)
)

const (
	defaultStringMaxLen = 256
	defaultTextMaxLen   = 65536
)

// ValidatePolicyName vérifie le nom d'une GPO.
func ValidatePolicyName(name string) error {
	n := strings.TrimSpace(name)
	if n == "" {
		return fmt.Errorf("le nom de la GPO est requis")
	}
	if !policyNameRe.MatchString(n) {
		return fmt.Errorf("nom de GPO invalide (2 à 64 caractères : lettres, chiffres, point, tiret, souligné) : %s", name)
	}
	return nil
}

// ValidateDescription vérifie la description d'une GPO.
func ValidateDescription(desc string) error {
	if len(desc) > 1024 {
		return fmt.Errorf("description trop longue (1024 caractères maximum)")
	}
	if strings.ContainsAny(desc, "\x00") {
		return fmt.Errorf("description contenant un caractère nul")
	}
	return nil
}

// ValidateModule vérifie et normalise un module dans le contexte d'une GPO du
// scope donné. Elle retourne les paramètres normalisés (valeurs par défaut
// appliquées, espaces superflus retirés) ; le module d'entrée n'est pas modifié.
func ValidateModule(policyScope Scope, m Module) (map[string]string, error) {
	if !IsValidPolicyScope(policyScope) {
		return nil, fmt.Errorf("scope de GPO invalide : %s", policyScope)
	}
	schema, ok := SchemaFor(m.Type)
	if !ok {
		return nil, fmt.Errorf("module inconnu : %s", m.Type)
	}
	// Garde-fou anti-élévation de privilège : vérifié avant toute autre chose.
	if err := CheckModuleScope(m.Type, policyScope); err != nil {
		return nil, err
	}

	// Refus des paramètres hors schéma.
	for key := range m.Params {
		if _, known := schema.Field(key); !known {
			return nil, fmt.Errorf("module %s : paramètre inconnu %q", m.Type, key)
		}
	}

	out := make(map[string]string, len(schema.Fields))
	for _, f := range schema.Fields {
		raw, provided := m.Params[f.Name]
		val := strings.TrimSpace(raw)
		if f.Type == FieldText {
			// Le contenu multiligne conserve son indentation interne ;
			// seuls les blancs de bord sont retirés.
			val = strings.Trim(raw, " \t\r\n")
		}
		if val == "" && !provided {
			val = f.Default
		}
		if val == "" {
			if f.Required && f.Default == "" {
				return nil, fmt.Errorf("module %s : le champ %q est requis", m.Type, f.Name)
			}
			if f.Required {
				val = f.Default
			} else {
				out[f.Name] = ""
				continue
			}
		}
		if err := validateFieldValue(m.Type, f, val, policyScope); err != nil {
			return nil, err
		}
		out[f.Name] = val
	}

	if err := validateModuleSemantics(m.Type, out); err != nil {
		return nil, err
	}
	return out, nil
}

// validateFieldValue applique le validateur du type de champ.
//
// Les champs dynamiques sont traités en premier et court-circuitent le switch de
// type : leur domaine est défini en base (liste, motif ou libre) et non par le
// code, donc le type ne sert plus qu'à choisir le widget d'affichage.
func validateFieldValue(moduleType string, f FieldSchema, val string, scope Scope) error {
	prefix := fmt.Sprintf("module %s, champ %s", moduleType, f.Name)

	if f.Dynamic {
		maxLen := f.MaxLen
		if maxLen == 0 {
			maxLen = defaultStringMaxLen
		}
		if len(val) > maxLen {
			return fmt.Errorf("%s : %d caractères maximum", prefix, maxLen)
		}
		if strings.ContainsAny(val, "\x00\n\r") {
			return fmt.Errorf("%s : caractère de contrôle interdit", prefix)
		}
		if err := checkAgainstRule(RuleFor(moduleType, f.Name), AllowedValuesFor(moduleType, f.Name), val); err != nil {
			return fmt.Errorf("%s : %v", prefix, err)
		}
		return nil
	}

	switch f.Type {
	case FieldString:
		maxLen := f.MaxLen
		if maxLen == 0 {
			maxLen = defaultStringMaxLen
		}
		if len(val) > maxLen {
			return fmt.Errorf("%s : %d caractères maximum", prefix, maxLen)
		}
		if strings.ContainsAny(val, "\x00\n\r") {
			return fmt.Errorf("%s : caractère de contrôle interdit", prefix)
		}

	case FieldText:
		maxLen := f.MaxLen
		if maxLen == 0 {
			maxLen = defaultTextMaxLen
		}
		if len(val) > maxLen {
			return fmt.Errorf("%s : %d caractères maximum", prefix, maxLen)
		}
		if strings.ContainsRune(val, '\x00') {
			return fmt.Errorf("%s : caractère nul interdit", prefix)
		}

	case FieldInt:
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("%s : entier attendu, reçu %q", prefix, val)
		}
		if !(f.Min == 0 && f.Max == 0) && (n < f.Min || n > f.Max) {
			return fmt.Errorf("%s : valeur hors bornes (%d à %d)", prefix, f.Min, f.Max)
		}

	case FieldBool:
		if val != "true" && val != "false" {
			return fmt.Errorf("%s : booléen attendu (true/false), reçu %q", prefix, val)
		}

	case FieldEnum:
		for _, opt := range f.Options {
			if opt == val {
				return nil
			}
		}
		return fmt.Errorf("%s : valeur %q hors liste autorisée", prefix, val)

	case FieldPath:
		maxLen := f.MaxLen
		if maxLen == 0 {
			maxLen = 512
		}
		if len(val) > maxLen {
			return fmt.Errorf("%s : %d caractères maximum", prefix, maxLen)
		}
		if err := CheckPath(val, scope); err != nil {
			return fmt.Errorf("%s : %v", prefix, err)
		}

	case FieldMode:
		if !modeRe.MatchString(val) {
			return fmt.Errorf("%s : permissions octales à 3 chiffres attendues (ex. 0644), reçu %q", prefix, val)
		}
		// Les bits setuid/setgid/sticky ne sont pas exprimables ici (3 chiffres
		// seulement) : c'est volontaire, une GPO ne doit pas pouvoir créer de
		// binaire setuid root.

	case FieldIdent:
		maxLen := f.MaxLen
		if maxLen == 0 {
			maxLen = 32
		}
		if len(val) > maxLen {
			return fmt.Errorf("%s : %d caractères maximum", prefix, maxLen)
		}
		if !identRe.MatchString(val) {
			return fmt.Errorf("%s : identifiant POSIX invalide (minuscules, chiffres, tiret, souligné) : %q", prefix, val)
		}
		if val == "root" && moduleType == ModuleSudoersRule {
			return fmt.Errorf("%s : attribuer des droits sudo au groupe root n'a pas de sens et masque une erreur de saisie", prefix)
		}

	case FieldEnvName:
		if !envNameRe.MatchString(val) {
			return fmt.Errorf("%s : nom de variable invalide : %q", prefix, val)
		}
		if IsForbiddenEnvName(val) {
			return fmt.Errorf("%s : la variable %s est interdite (détournement possible de l'exécution de binaires)", prefix, strings.ToUpper(val))
		}

	case FieldCron:
		fields := strings.Fields(val)
		if len(fields) != 5 {
			return fmt.Errorf("%s : expression cron à 5 champs attendue, reçu %q", prefix, val)
		}
		for i, cf := range fields {
			if !cronFieldRe.MatchString(cf) {
				return fmt.Errorf("%s : champ cron %d invalide (%q)", prefix, i+1, cf)
			}
		}

	default:
		return fmt.Errorf("%s : type de champ non géré (%s)", prefix, f.Type)
	}
	return nil
}

// validateModuleSemantics applique les règles de cohérence entre champs d'un
// même module, celles qu'un validateur champ par champ ne peut pas voir.
func validateModuleSemantics(moduleType string, p map[string]string) error {
	switch moduleType {
	case ModuleSystemdService:
		if p["masked"] == "true" && (p["state"] == "started" || p["state"] == "restarted") {
			return fmt.Errorf("module %s : une unité masquée ne peut pas être démarrée (masked=true et state=%s)", moduleType, p["state"])
		}
		if p["masked"] == "true" && p["enabled"] == "enabled" {
			return fmt.Errorf("module %s : une unité masquée ne peut pas être activée au démarrage", moduleType)
		}

	case ModuleSudoersRule:
		// Le jeu de commandes est une définition : on refuse une valeur qui n'a
		// pas de contenu en base, sinon l'agent recevrait un nom de jeu vide et
		// générerait un fichier sudoers sans effet — ou pire, incomplet.
		set := p["command_set"]
		def, found := Restrictions().Definition(ModuleSudoersRule, "command_set", set)
		if !found {
			return fmt.Errorf("module %s : le jeu de commandes %q n'est pas défini ; créez-le dans Admin → GPO → Restrictions", moduleType, set)
		}
		if len(def.Lines()) == 0 {
			return fmt.Errorf("module %s : le jeu de commandes %q est vide", moduleType, set)
		}
		if p["nopasswd"] == "true" && grantsAllCommands(def) {
			return fmt.Errorf("module %s : le jeu %q autorise toutes les commandes ; combiné à NOPASSWD cela équivaut à un accès root sans authentification, refusé", moduleType, set)
		}

	case ModuleFileDeploy:
		if p["state"] == "present" && p["content"] == "" {
			return fmt.Errorf("module %s : contenu requis pour déposer un fichier (state=present)", moduleType)
		}
		if p["state"] == "absent" && p["content"] != "" {
			return fmt.Errorf("module %s : un contenu est renseigné alors que l'état demandé est absent", moduleType)
		}

	case ModulePackage:
		if v := p["version"]; v != "" {
			if !packageVersionRe.MatchString(v) {
				return fmt.Errorf("module %s : version épinglée invalide (%q)", moduleType, v)
			}
			if p["state"] == "absent" {
				return fmt.Errorf("module %s : une version ne peut pas être épinglée pour un paquet à retirer", moduleType)
			}
		}

	case ModuleSSHServerConfig:
		allUnchanged := true
		for _, k := range []string{"permit_root_login", "password_authentication", "pubkey_authentication", "allow_tcp_forwarding", "x11_forwarding"} {
			if p[k] != "" && p[k] != "unchanged" {
				allUnchanged = false
			}
		}
		if allUnchanged && p["max_auth_tries"] == "" && p["client_alive_interval"] == "" && p["banner_text"] == "" {
			return fmt.Errorf("module %s : aucun réglage renseigné, le module serait sans effet", moduleType)
		}
		if p["password_authentication"] == "no" && p["pubkey_authentication"] == "no" {
			return fmt.Errorf("module %s : désactiver à la fois l'authentification par mot de passe et par clé rendrait les machines inaccessibles en SSH", moduleType)
		}
	}
	return nil
}

// grantsAllCommands indique si un jeu de commandes équivaut à un accès total.
func grantsAllCommands(def ValueDefinition) bool {
	lines := def.Lines()
	return len(lines) == 1 && lines[0] == "ALL"
}

// ValidatePolicy valide une GPO complète : nom, scope, description, puis chaque
// module. Les paramètres normalisés et l'ordre d'application sont écrits dans p.
func ValidatePolicy(p *Policy) error {
	if p == nil {
		return fmt.Errorf("GPO nulle")
	}
	if err := ValidatePolicyName(p.Name); err != nil {
		return err
	}
	if err := ValidateDescription(p.Description); err != nil {
		return err
	}
	if !IsValidPolicyScope(p.Scope) {
		return fmt.Errorf("scope invalide %q (attendu : %s ou %s)", p.Scope, ScopeMachine, ScopeUser)
	}
	p.Name = strings.TrimSpace(p.Name)
	p.Description = strings.TrimSpace(p.Description)

	seen := map[string]bool{}
	for i := range p.Modules {
		params, err := ValidateModule(p.Scope, p.Modules[i])
		if err != nil {
			return fmt.Errorf("module %d : %v", i+1, err)
		}
		schema, _ := SchemaFor(p.Modules[i].Type)
		p.Modules[i].Params = params
		p.Modules[i].Scope = p.Scope
		p.Modules[i].ApplyOrder = schema.ApplyOrder

		// Détection des doublons pour les modules dont la clé naturelle rend un
		// second exemplaire contradictoire (deux valeurs pour la même clé sysctl,
		// deux états pour le même service, deux contenus pour le même fichier).
		if key := moduleIdentity(p.Modules[i]); key != "" {
			if seen[key] {
				return fmt.Errorf("module %d : doublon, %s est déjà réglé par un autre module de cette GPO", i+1, key)
			}
			seen[key] = true
		}
	}
	SortModules(p.Modules)
	return nil
}

// moduleIdentity retourne la clé naturelle d'un module, ou "" si le module peut
// légitimement apparaître plusieurs fois.
func moduleIdentity(m Module) string {
	switch m.Type {
	case ModuleSysctl:
		return "sysctl " + m.Params["key"]
	case ModuleSystemdService:
		return "le service " + m.Params["service"]
	case ModulePackage:
		return "le paquet " + m.Params["package"]
	case ModuleFileDeploy:
		return "le fichier " + m.Params["path"]
	case ModuleUserEnv:
		return "la variable " + strings.ToUpper(m.Params["name"])
	case ModuleUserCron:
		return "la tâche " + m.Params["command_id"]
	case ModuleDirectoryManage:
		return "le répertoire " + m.Params["path"]
	case ModuleTemplatedFile:
		return "le fichier " + m.Params["path"]
	case ModuleTrustedCA:
		return "l'autorité de certification " + m.Params["name"]
	case ModulePackageRepo:
		return "le dépôt " + m.Params["name"]
	case ModuleFirewallRule:
		return "la règle de pare-feu " + m.Params["port"] + "/" + m.Params["protocol"]
	case ModuleDNSResolver:
		return "la résolution DNS"
	case ModuleFileACL:
		return "l'ACL " + m.Params["kind"] + ":" + m.Params["target"] + " sur " + m.Params["path"]
	case ModuleBootParams:
		return "le paramètre de démarrage " + m.Params["parameter"]
	case ModuleKernelModulePolicy:
		return "le module noyau " + m.Params["module"]
	case ModuleSSHKnownHosts:
		return "l'hôte SSH connu " + m.Params["host"]
	case ModuleAuditdRule:
		return "la règle d'audit sur " + m.Params["path"]
	case ModulePAMPolicy:
		return "la politique de mot de passe"
	case ModuleLocalAccountPolicy:
		return "la politique des comptes locaux"
	case ModuleSELinuxMode:
		return "le mode SELinux"
	case ModuleNTPConfig:
		return "la synchronisation horaire"
	case ModuleLogPolicy:
		return "la rétention des journaux"
	case ModuleUpdatePolicy:
		return "la politique de mise à jour"
	case ModuleSystemEnv:
		return "la variable système " + strings.ToUpper(m.Params["name"])
	case ModuleResourceLimits:
		return "la limite " + m.Params["item"] + " pour " + m.Params["domain"]
	case ModuleFileRetention:
		return "la purge de " + m.Params["directory"] + "/" + m.Params["pattern"]
	case ModuleUserGroupMembership:
		return "l'appartenance au groupe " + m.Params["group"]
	case ModuleUserShell:
		return "le shell de connexion"
	case ModuleUserPasswordPolicy:
		return "l'expiration du mot de passe"
	case ModuleUserSSHClientConfig:
		return "l'alias SSH " + m.Params["host_alias"]
	case ModuleUserGitConfig:
		return "la clé git " + m.Params["key"]
	case ModuleUserResourceLimits:
		return "le quota de ressources"
	case ModuleSSHServerConfig, ModuleSudoersRule:
		if m.Type == ModuleSudoersRule {
			return "les droits sudo du groupe " + m.Params["group"]
		}
		return "la configuration SSH serveur"
	}
	return ""
}

// SortModules trie les modules par ordre d'application puis par type, pour que
// l'application soit déterministe quel que soit l'ordre de saisie ou de lecture
// en base.
func SortModules(modules []Module) {
	sort.SliceStable(modules, func(i, j int) bool {
		if modules[i].ApplyOrder != modules[j].ApplyOrder {
			return modules[i].ApplyOrder < modules[j].ApplyOrder
		}
		if modules[i].Type != modules[j].Type {
			return modules[i].Type < modules[j].Type
		}
		return moduleIdentity(modules[i]) < moduleIdentity(modules[j])
	})
}

// EncodeParams sérialise les paramètres d'un module pour la colonne JSON.
// Les clés sont ordonnées afin que la sortie soit reproductible (diff et hash
// stables d'une écriture à l'autre).
func EncodeParams(params map[string]string) (string, error) {
	if params == nil {
		params = map[string]string{}
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteString("{")
	for i, k := range keys {
		kb, err := json.Marshal(k)
		if err != nil {
			return "", err
		}
		vb, err := json.Marshal(params[k])
		if err != nil {
			return "", err
		}
		if i > 0 {
			sb.WriteString(",")
		}
		sb.Write(kb)
		sb.WriteString(":")
		sb.Write(vb)
	}
	sb.WriteString("}")
	return sb.String(), nil
}

// DecodeParams désérialise la colonne JSON des paramètres d'un module.
func DecodeParams(raw string) (map[string]string, error) {
	params := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return params, nil
	}
	if err := json.Unmarshal([]byte(raw), &params); err != nil {
		return nil, fmt.Errorf("paramètres de module illisibles : %v", err)
	}
	return params, nil
}

// CanonicalJSON produit une représentation canonique de la GPO, indépendante de
// l'ordre de lecture en base. C'est la forme qui sera signée par le serveur
// central et hachée pour l'idempotence côté agent.
func CanonicalJSON(p Policy) ([]byte, error) {
	modules := append([]Module(nil), p.Modules...)
	SortModules(modules)

	type canonicalModule struct {
		Type       string            `json:"type"`
		Scope      Scope             `json:"scope"`
		ApplyOrder int               `json:"apply_order"`
		Params     map[string]string `json:"params"`
		// Le mode de dérive entre dans l'empreinte de POLITIQUE, et volontairement
		// pas dans celle du MODULE (voir ModuleFingerprint).
		//
		// Dans l'empreinte de politique, parce que sans cela un passage en audit
		// n'atteindrait jamais le parc : le serveur répondrait « rien à faire »
		// aux agents dont la politique est par ailleurs identique, et le réglage
		// resterait lettre morte jusqu'à la prochaine modification de contenu.
		//
		// Hors de l'empreinte de module, parce que changer le mode ne change pas
		// ce qui doit être posé sur la machine. L'agent retéléchargera le
		// document et trouvera tous ses modules « unchanged » : aucun service
		// relancé, aucun paquet réinstallé, pour un simple changement de
		// politique de correction.
		DriftMode DriftMode `json:"drift_mode,omitempty"`
		// Le contenu des définitions référencées entre dans l'empreinte : modifier
		// la liste de commandes d'un jeu sudo ne change aucun paramètre de module,
		// mais change bel et bien ce qui sera appliqué. Sans cela le serveur
		// répondrait « rien à faire » et le parc garderait l'ancienne règle.
		Definitions map[string]string `json:"definitions,omitempty"`
	}
	type canonicalPolicy struct {
		Name    string            `json:"name"`
		Scope   Scope             `json:"scope"`
		Version int               `json:"version"`
		Enabled bool              `json:"enabled"`
		Modules []canonicalModule `json:"modules"`
	}

	cp := canonicalPolicy{Name: p.Name, Scope: p.Scope, Version: p.Version, Enabled: p.Enabled}
	for _, m := range modules {
		cp.Modules = append(cp.Modules, canonicalModule{
			Type: m.Type, Scope: m.Scope, ApplyOrder: m.ApplyOrder, Params: m.Params,
			DriftMode:   m.DriftMode,
			Definitions: definitionsForHash(m),
		})
	}
	return json.Marshal(cp)
}

// PolicyHash retourne le SHA-256 de la forme canonique de la GPO. L'agent
// client s'en servira comme marqueur d'idempotence : tant que le hash est
// inchangé, il n'y a rien à réappliquer.
func PolicyHash(p Policy) (string, error) {
	data, err := CanonicalJSON(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}
