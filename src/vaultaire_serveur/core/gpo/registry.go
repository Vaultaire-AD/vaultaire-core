package gpo

import "sort"

// Catalogue des modules GPO.
//
// Le catalogue définit les TYPES de modules et la FORME de leurs champs : c'est
// la partie structurelle, qui reste dans le code parce qu'elle correspond à ce
// que l'agent client sait faire. Ajouter un type ici sans écrire le handler
// correspondant côté agent donnerait un module sans effet.
//
// Le DOMAINE de valeurs des champs marqués Dynamic, lui, vit en base et est
// éditable par le groupe superadmin (voir restrictions.go). C'est ce qui permet
// d'accueillir un besoin custom — un service de monitoring maison, un paquet
// interne — sans toucher au code : soit en ajoutant la valeur à la liste, soit
// en passant le champ en mode motif.
//
// ApplyOrder impose l'ordre d'application indépendamment de l'ordre de saisie :
// réseau/sécurité (10-19), puis paquets/services (20-29), puis fichiers (30-39),
// puis personnalisation utilisateur (40+).

// Types de modules du catalogue.
const (
	ModuleSSHServerConfig = "ssh_server_config"
	ModuleSysctl          = "sysctl"
	ModuleSudoersRule     = "sudoers_rule"
	ModulePackage         = "package"
	ModuleSystemdService  = "systemd_service"
	ModuleFileDeploy      = "file_deploy"
	ModuleUserEnv         = "user_env"
	ModuleUserCron        = "user_cron"
)

// Catégories affichées dans l'interface web.
const (
	CategorySecurity = "Sécurité & réseau"
	CategorySystem   = "Système & services"
	CategoryFiles    = "Fichiers"
	CategoryUser     = "Environnement utilisateur"
)

// baseCatalog est le catalogue tel que défini dans le code, avant résolution des
// restrictions en base. Les champs Dynamic y ont Options vide : leurs valeurs
// sont injectées par resolveSchema.
var baseCatalog = []ModuleSchema{
	{
		Type:        ModuleSSHServerConfig,
		Label:       "Configuration SSH serveur",
		Category:    CategorySecurity,
		Description: "Règle sshd via un fragment dédié /etc/ssh/sshd_config.d/99-vaultaire-gpo.conf. Le fichier principal n'est jamais modifié et la configuration est validée (sshd -t) avant rechargement.",
		Scope:       ScopeMachine,
		ApplyOrder:  10,
		Fields: []FieldSchema{
			{Name: "permit_root_login", Label: "PermitRootLogin", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no", "prohibit-password", "forced-commands-only"},
				Default: "unchanged", Required: true},
			{Name: "password_authentication", Label: "PasswordAuthentication", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged", Required: true},
			{Name: "pubkey_authentication", Label: "PubkeyAuthentication", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged", Required: true},
			{Name: "max_auth_tries", Label: "MaxAuthTries", Type: FieldInt, Min: 1, Max: 10,
				Help: "Laisser vide pour ne pas imposer de valeur."},
			{Name: "client_alive_interval", Label: "ClientAliveInterval (s)", Type: FieldInt, Min: 0, Max: 86400,
				Help: "Laisser vide pour ne pas imposer de valeur."},
			{Name: "allow_tcp_forwarding", Label: "AllowTcpForwarding", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no", "local", "remote"}, Default: "unchanged"},
			{Name: "x11_forwarding", Label: "X11Forwarding", Type: FieldEnum,
				Options: []string{"unchanged", "yes", "no"}, Default: "unchanged"},
			{Name: "banner_text", Label: "Bannière de connexion", Type: FieldText, MaxLen: 4096,
				Help: "Déposée dans un fichier dédié et référencée par la directive Banner."},
		},
	},
	{
		Type:        ModuleSysctl,
		Label:       "Paramètre noyau (sysctl)",
		Category:    CategorySecurity,
		Description: "Fixe une clé sysctl. Écrit dans /etc/sysctl.d/, jamais dans /etc/sysctl.conf. Les clés disponibles sont éditables dans Admin → GPO → Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  11,
		Fields: []FieldSchema{
			{Name: "key", Label: "Clé", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, Dynamic: true, MaxLen: 128,
				Help: "Forme acceptée définie par la règle sysctl/value dans les Restrictions."},
		},
	},
	{
		Type:        ModuleSudoersRule,
		Label:       "Droits sudo (par groupe)",
		Category:    CategorySecurity,
		Description: "Génère un fichier /etc/sudoers.d/ depuis un template contrôlé côté agent. Aucune ligne sudoers brute n'est transmise : seuls un groupe et un identifiant de jeu de commandes circulent.",
		Scope:       ScopeMachine,
		ApplyOrder:  12,
		Fields: []FieldSchema{
			{Name: "group", Label: "Groupe POSIX bénéficiaire", Type: FieldIdent, Required: true, MaxLen: 32},
			{Name: "command_set", Label: "Jeu de commandes", Type: FieldEnum, Required: true,
				Dynamic: true, Default: "service_control", MaxLen: 64},
			{Name: "nopasswd", Label: "Sans mot de passe (NOPASSWD)", Type: FieldBool, Default: "false",
				Help: "À éviter : supprime la ré-authentification avant élévation."},
		},
	},
	{
		Type:        ModulePackage,
		Label:       "Paquet logiciel",
		Category:    CategorySystem,
		Description: "Garantit la présence ou l'absence d'un paquet. Appliqué avant les modules de service, pour qu'une unité dépendante d'un paquet existe au moment de son activation. Les paquets disponibles sont éditables dans les Restrictions.",
		Scope:       ScopeMachine,
		ApplyOrder:  20,
		Fields: []FieldSchema{
			{Name: "package", Label: "Paquet", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
			{Name: "version", Label: "Version épinglée", Type: FieldString, MaxLen: 64,
				Help: "Laisser vide pour la dernière version disponible dans les dépôts configurés."},
		},
	},
	{
		Type:        ModuleSystemdService,
		Label:       "Service systemd",
		Category:    CategorySystem,
		Description: "Force l'état d'une unité systemd (activation au boot, état courant, masquage). Les unités disponibles sont éditables dans les Restrictions — c'est là qu'on déclare un service maison.",
		Scope:       ScopeMachine,
		ApplyOrder:  21,
		Fields: []FieldSchema{
			{Name: "service", Label: "Unité", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 128},
			{Name: "enabled", Label: "Activation au démarrage", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "enabled", "disabled"}, Default: "unchanged"},
			{Name: "state", Label: "État courant", Type: FieldEnum, Required: true,
				Options: []string{"unchanged", "started", "stopped", "restarted"}, Default: "unchanged"},
			{Name: "masked", Label: "Masquer l'unité", Type: FieldBool, Default: "false",
				Help: "Le masquage rend l'unité indémarrable, y compris par dépendance."},
		},
	},
	{
		Type:        ModuleFileDeploy,
		Label:       "Déploiement de fichier",
		Category:    CategoryFiles,
		Description: "Dépose un fichier avec contenu, permissions et propriétaire. Les emplacements autorisés et refusés sont éditables dans les Restrictions ; en scope user, le chemin s'exprime sous " + userHomePlaceholder + "/.",
		Scope:       ScopeBoth,
		ApplyOrder:  30,
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512,
				Help: "Scope machine : chemin absolu hors zones refusées. Scope user : " + userHomePlaceholder + "/chemin/relatif."},
			{Name: "content", Label: "Contenu", Type: FieldText, MaxLen: 262144},
			{Name: "mode", Label: "Permissions", Type: FieldMode, Required: true, Default: "0644",
				Help: "Notation octale à 3 chiffres. Les bits setuid/setgid ne sont pas exprimables."},
			{Name: "owner", Label: "Propriétaire", Type: FieldIdent, MaxLen: 32,
				Help: "Laisser vide pour root en scope machine, pour l'utilisateur cible en scope user."},
			{Name: "group", Label: "Groupe", Type: FieldIdent, MaxLen: 32},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleUserEnv,
		Label:       "Variable d'environnement utilisateur",
		Category:    CategoryUser,
		Description: "Définit une variable dans un fichier dédié sourcé depuis le shell de l'utilisateur (bloc balisé, le .bashrc n'est jamais réécrit). La liste des variables interdites est éditable dans les Restrictions.",
		Scope:       ScopeUser,
		ApplyOrder:  40,
		Fields: []FieldSchema{
			{Name: "name", Label: "Nom", Type: FieldEnvName, Required: true, MaxLen: 64},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 1024},
		},
	},
	{
		Type:        ModuleUserCron,
		Label:       "Tâche planifiée utilisateur",
		Category:    CategoryUser,
		Description: "Crée un timer systemd --user. La tâche référence un identifiant de commande implémenté côté agent ; la liste des identifiants est éditable dans les Restrictions.",
		Scope:       ScopeUser,
		ApplyOrder:  41,
		Fields: []FieldSchema{
			{Name: "schedule", Label: "Planification (cron 5 champs)", Type: FieldCron, Required: true,
				Default: "0 9 * * *", MaxLen: 128},
			{Name: "command_id", Label: "Commande", Type: FieldEnum, Required: true, Dynamic: true, MaxLen: 64},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
}

// baseIndex permet une résolution par type en O(1).
var baseIndex = func() map[string]ModuleSchema {
	m := make(map[string]ModuleSchema, len(baseCatalog))
	for _, s := range baseCatalog {
		m[s.Type] = s
	}
	return m
}()

// resolveSchema renseigne les champs Dynamic depuis les restrictions en vigueur.
//
// Le schéma est copié en profondeur (le slice Fields et chaque slice Options),
// pour qu'une résolution ne modifie jamais le catalogue de base. Sans cette
// copie, deux appels concurrents se marcheraient dessus.
func resolveSchema(s ModuleSchema) ModuleSchema {
	rs := Restrictions()
	resolved := s
	resolved.Fields = make([]FieldSchema, len(s.Fields))

	for i, f := range s.Fields {
		field := f
		if f.Options != nil {
			field.Options = append([]string(nil), f.Options...)
		}
		if f.Dynamic {
			rule := rs.Rule(s.Type, f.Name)
			field.Mode = rule.Mode
			field.AllowPattern = rule.AllowPattern
			field.DenyPattern = rule.DenyPattern
			field.Options = rs.Values(s.Type, f.Name)

			// Hors mode liste, la valeur est saisie librement : le type d'entrée
			// devient une chaîne pour que l'interface web affiche un champ texte
			// plutôt qu'un menu déroulant vide.
			if rule.Mode != FieldModeList {
				field.Type = FieldString
			}
		}
		resolved.Fields[i] = field
	}
	return resolved
}

// BaseSchemaFor retourne le schéma brut d'un module, sans consulter les
// restrictions. Utilisé par les vérifications structurelles (scope), qui n'ont
// pas besoin du domaine de valeurs et ne doivent pas dépendre de la base.
func BaseSchemaFor(moduleType string) (ModuleSchema, bool) {
	s, ok := baseIndex[moduleType]
	return s, ok
}

// SchemaFor retourne le schéma résolu d'un module : forme issue du code, domaine
// de valeurs issu de la base.
func SchemaFor(moduleType string) (ModuleSchema, bool) {
	s, ok := baseIndex[moduleType]
	if !ok {
		return ModuleSchema{}, false
	}
	return resolveSchema(s), true
}

// Catalog retourne le catalogue résolu, trié par ordre d'application puis libellé.
func Catalog() []ModuleSchema {
	out := make([]ModuleSchema, 0, len(baseCatalog))
	for _, s := range baseCatalog {
		out = append(out, resolveSchema(s))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ApplyOrder != out[j].ApplyOrder {
			return out[i].ApplyOrder < out[j].ApplyOrder
		}
		return out[i].Label < out[j].Label
	})
	return out
}

// CatalogForScope retourne les modules utilisables dans une GPO de ce scope.
func CatalogForScope(policyScope Scope) []ModuleSchema {
	var out []ModuleSchema
	for _, s := range Catalog() {
		if s.AllowedInScope(policyScope) {
			out = append(out, s)
		}
	}
	return out
}

// ModuleTypes retourne tous les types du catalogue.
func ModuleTypes() []string {
	out := make([]string, 0, len(baseCatalog))
	for _, s := range baseCatalog {
		out = append(out, s.Type)
	}
	sort.Strings(out)
	return out
}

// ModuleLabel retourne le libellé lisible d'un type de module.
func ModuleLabel(moduleType string) string {
	if s, ok := baseIndex[moduleType]; ok {
		return s.Label
	}
	return moduleType
}

// DefaultParams construit la map de paramètres par défaut d'un module, utilisée
// pour préremplir les formulaires web.
func DefaultParams(moduleType string) map[string]string {
	schema, ok := SchemaFor(moduleType)
	if !ok {
		return nil
	}
	params := make(map[string]string, len(schema.Fields))
	for _, f := range schema.Fields {
		params[f.Name] = f.Default
	}
	return params
}

// CategoriesForScope retourne les catégories présentes pour un scope, dans
// l'ordre d'application, pour grouper l'affichage web.
func CategoriesForScope(policyScope Scope) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range CatalogForScope(policyScope) {
		if !seen[s.Category] {
			seen[s.Category] = true
			out = append(out, s.Category)
		}
	}
	return out
}
