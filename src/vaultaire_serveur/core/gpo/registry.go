package gpo

import "sort"

// Catalogue des modules GPO.
//
// C'est la surface d'attaque complète et bornée du système : un administrateur
// ne peut composer une GPO qu'avec ces types, paramétrés par ces champs, avec
// ces valeurs. Ajouter une capacité = ajouter une entrée ici et l'implémenter
// côté agent client — il n'existe aucun chemin pour exécuter autre chose.
//
// ApplyOrder impose l'ordre d'application indépendamment de l'ordre de saisie :
// réseau/sécurité (10-19), puis paquets/services (20-29), puis fichiers (30-39),
// puis personnalisation utilisateur (40+). Un réordonnancement accidentel de la
// liste en base ne peut donc pas changer le résultat.

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

var catalog = []ModuleSchema{
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
		Description: "Fixe une clé sysctl parmi une liste blanche de durcissement. Écrit dans /etc/sysctl.d/, jamais dans /etc/sysctl.conf.",
		Scope:       ScopeMachine,
		ApplyOrder:  11,
		Fields: []FieldSchema{
			{Name: "key", Label: "Clé", Type: FieldEnum, Required: true, Options: allowedSysctlKeys},
			{Name: "value", Label: "Valeur", Type: FieldString, Required: true, MaxLen: 64,
				Help: "Valeur numérique ou liste d'entiers séparés par des espaces."},
		},
	},
	{
		Type:        ModuleSudoersRule,
		Label:       "Droits sudo (par groupe)",
		Category:    CategorySecurity,
		Description: "Génère un fichier /etc/sudoers.d/ depuis un template contrôlé côté agent. Aucune ligne sudoers brute n'est acceptée : seuls un groupe et un jeu de commandes prédéfini sont transmis.",
		Scope:       ScopeMachine,
		ApplyOrder:  12,
		Fields: []FieldSchema{
			{Name: "group", Label: "Groupe POSIX bénéficiaire", Type: FieldIdent, Required: true, MaxLen: 32},
			{Name: "command_set", Label: "Jeu de commandes", Type: FieldEnum, Required: true,
				Options: allowedSudoCommandSets, Default: "service_control"},
			{Name: "nopasswd", Label: "Sans mot de passe (NOPASSWD)", Type: FieldBool, Default: "false",
				Help: "À éviter : supprime la ré-authentification avant élévation."},
		},
	},
	{
		Type:        ModulePackage,
		Label:       "Paquet logiciel",
		Category:    CategorySystem,
		Description: "Garantit la présence ou l'absence d'un paquet de la liste blanche. Appliqué avant les modules de service, pour qu'une unité dépendante d'un paquet existe au moment de son activation.",
		Scope:       ScopeMachine,
		ApplyOrder:  20,
		Fields: []FieldSchema{
			{Name: "package", Label: "Paquet", Type: FieldEnum, Required: true, Options: allowedPackages},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
	{
		Type:        ModuleSystemdService,
		Label:       "Service systemd",
		Category:    CategorySystem,
		Description: "Force l'état d'une unité systemd de la liste blanche (activation au boot, état courant, masquage).",
		Scope:       ScopeMachine,
		ApplyOrder:  21,
		Fields: []FieldSchema{
			{Name: "service", Label: "Unité", Type: FieldEnum, Required: true, Options: allowedServices},
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
		Description: "Dépose un fichier avec contenu, permissions et propriétaire. En scope user, le chemin doit être exprimé sous " + userHomePlaceholder + "/ ; les chemins système sont refusés localement par l'agent même si le serveur les envoie.",
		Scope:       ScopeBoth,
		ApplyOrder:  30,
		Fields: []FieldSchema{
			{Name: "path", Label: "Chemin", Type: FieldPath, Required: true, MaxLen: 512,
				Help: "Scope machine : chemin absolu hors zones protégées. Scope user : " + userHomePlaceholder + "/chemin/relatif."},
			{Name: "content", Label: "Contenu", Type: FieldText, MaxLen: 65536},
			{Name: "mode", Label: "Permissions", Type: FieldMode, Required: true, Default: "0644",
				Help: "Notation octale. Les bits setuid/setgid sont refusés."},
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
		Description: "Définit une variable dans un fichier dédié sourcé depuis le shell de l'utilisateur (bloc balisé, le .bashrc n'est jamais réécrit). Les variables permettant de détourner l'exécution de binaires sont refusées.",
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
		Description: "Crée un timer systemd --user. La tâche référence un identifiant de commande implémenté côté agent : aucune ligne de shell ne transite dans la GPO.",
		Scope:       ScopeUser,
		ApplyOrder:  41,
		Fields: []FieldSchema{
			{Name: "schedule", Label: "Planification (cron 5 champs)", Type: FieldCron, Required: true,
				Default: "0 9 * * *", MaxLen: 128},
			{Name: "command_id", Label: "Commande", Type: FieldEnum, Required: true, Options: allowedCronCommandIDs},
			{Name: "state", Label: "État attendu", Type: FieldEnum, Required: true,
				Options: []string{"present", "absent"}, Default: "present"},
		},
	},
}

// schemaIndex permet une résolution par type en O(1).
var schemaIndex = func() map[string]ModuleSchema {
	m := make(map[string]ModuleSchema, len(catalog))
	for _, s := range catalog {
		m[s.Type] = s
	}
	return m
}()

// Catalog retourne le catalogue complet des modules, trié par ordre
// d'application puis par libellé.
func Catalog() []ModuleSchema {
	out := append([]ModuleSchema(nil), catalog...)
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

// SchemaFor retourne le schéma d'un type de module.
func SchemaFor(moduleType string) (ModuleSchema, bool) {
	s, ok := schemaIndex[moduleType]
	return s, ok
}

// ModuleTypes retourne tous les types du catalogue.
func ModuleTypes() []string {
	out := make([]string, 0, len(catalog))
	for _, s := range Catalog() {
		out = append(out, s.Type)
	}
	return out
}

// DefaultParams construit la map de paramètres par défaut d'un module,
// utilisée pour préremplir les formulaires web.
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
