package gpo

// Jeu de restrictions par défaut.
//
// C'est exactement le socle qui était codé en dur avant l'externalisation : une
// base neuve démarre donc avec les mêmes protections, et db_gpo s'en sert comme
// données de peuplement initial (seed). C'est aussi le repli utilisé quand aucun
// fournisseur n'est installé ou que la base est injoignable — une panne ne doit
// pas se traduire par une absence de restrictions.
//
// Ces valeurs ne sont PAS une limite : le groupe superadmin `vaultaire` peut
// ajouter, retirer ou remplacer n'importe laquelle depuis Admin → GPO →
// Restrictions, y compris passer un champ en mode motif ou libre.

// defaultServices liste les unités systemd gérables au départ.
var defaultServices = []string{
	"apparmor.service", "auditd.service", "avahi-daemon.service", "avahi-daemon.socket",
	"chronyd.service", "cups.service", "cups.socket", "firewalld.service",
	"nftables.service", "nfs-server.service", "ntp.service", "rpcbind.service",
	"rpcbind.socket", "rsyslog.service", "smbd.service", "snapd.service",
	"systemd-timesyncd.service", "telnet.socket", "tftp.socket", "vsftpd.service",
}

// defaultSysctlKeys liste les clés sysctl réglables au départ (durcissement).
var defaultSysctlKeys = []string{
	"kernel.dmesg_restrict", "kernel.kptr_restrict", "kernel.randomize_va_space",
	"kernel.sysrq", "kernel.unprivileged_bpf_disabled", "kernel.yama.ptrace_scope",
	"net.ipv4.conf.all.accept_redirects", "net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.all.log_martians", "net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.all.send_redirects", "net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.ip_forward", "net.ipv4.tcp_syncookies", "net.ipv6.conf.all.accept_ra",
	"net.ipv6.conf.all.accept_redirects", "net.ipv6.conf.all.disable_ipv6",
	"vm.mmap_min_addr", "vm.swappiness",
}

// defaultPackages liste les paquets gérables au départ.
var defaultPackages = []string{
	"aide", "auditd", "chrony", "cups", "curl", "fail2ban", "git", "htop",
	"nftables", "rsh-client", "rsync", "telnet", "tmux", "unzip", "vim",
	"vsftpd", "xinetd", "zsh",
}

// defaultSudoCommandSets liste les jeux de commandes sudo initiaux, avec leur
// contenu réel. Contrairement aux autres listes, ce ne sont pas de simples noms :
// un jeu de commandes n'a de sens que si l'on sait ce qu'il autorise, et c'est ce
// contenu que l'agent rend dans le fichier /etc/sudoers.d/ généré.
//
// Un administrateur peut créer ses propres jeux depuis
// Admin → GPO → Restrictions, sans qu'aucun code n'ait à changer.
var defaultSudoCommandSets = []struct {
	Name    string
	Payload string
	Note    string
}{
	{"ALL", "ALL", "toutes les commandes — équivalent à un accès root complet"},
	{"pkg_management",
		"/usr/bin/apt-get\n/usr/bin/apt\n/usr/bin/dnf\n/usr/bin/yum\n/usr/bin/rpm\n/usr/bin/dpkg",
		"installation et mise à jour de paquets"},
	{"service_control",
		"/usr/bin/systemctl start\n/usr/bin/systemctl stop\n/usr/bin/systemctl restart\n/usr/bin/systemctl reload\n/usr/bin/systemctl status",
		"pilotage des services systemd"},
	{"network_diagnostics",
		"/usr/bin/ping\n/usr/sbin/ip\n/usr/bin/ss\n/usr/sbin/tcpdump\n/usr/bin/traceroute\n/usr/bin/dig",
		"diagnostic réseau"},
	{"log_read",
		"/usr/bin/journalctl\n/usr/bin/dmesg\n/usr/bin/tail\n/usr/bin/less",
		"lecture des journaux système"},
	{"disk_read",
		"/usr/bin/df\n/usr/bin/du\n/usr/sbin/blkid\n/usr/bin/lsblk\n/usr/bin/smartctl",
		"inspection du stockage"},
}

// defaultSysctlValuePattern borne les valeurs sysctl acceptées au départ : un
// entier ou une liste d'entiers, ce qui couvre l'immense majorité des clés de
// durcissement. Une clé custom attendant une valeur textuelle se traite en
// élargissant ce motif depuis l'interface Restrictions.
const defaultSysctlValuePattern = `^-?[0-9]+( -?[0-9]+)*$`

// defaultCronCommandIDs liste les tâches planifiables en scope user au départ.
// Même remarque : l'identifiant réfère à une implémentation côté agent.
var defaultCronCommandIDs = []string{
	"backup_home", "cleanup_tmp", "report_disk_usage", "sync_dotfiles", "rotate_user_logs",
}

// defaultDeniedPaths liste les préfixes refusés dans tous les scopes au départ.
// Ce sont les fichiers qui gouvernent eux-mêmes les privilèges, plus l'état local
// de l'agent Vaultaire.
var defaultDeniedPaths = []struct {
	Prefix string
	Note   string
}{
	{"/etc/pam.d/", "pile d'authentification : modifiable = contournement de l'auth"},
	{"/etc/security/", "configuration PAM (pwquality, faillock, limits)"},
	{"/etc/sudoers", "élévation de privilège directe"},
	{"/etc/sudoers.d/", "élévation de privilège directe"},
	{"/etc/shadow", "empreintes de mots de passe locaux"},
	{"/etc/gshadow", "empreintes de mots de passe de groupes"},
	{"/etc/passwd", "comptes locaux et shells"},
	{"/etc/group", "appartenances de groupes locaux"},
	{"/etc/ssh/sshd_config", "fichier principal sshd : utilisez le module ssh_server_config"},
	{"/etc/ssh/ssh_host_", "clés d'hôte du serveur SSH"},
	{"/etc/vaultaire/", "configuration de l'agent Vaultaire"},
	{"/var/lib/vaultaire/", "état local de l'agent (versions de GPO appliquées)"},
	{"/lib/security/", "modules PAM"},
	{"/lib64/security/", "modules PAM"},
	{"/usr/lib/security/", "modules PAM"},
	{"/usr/lib64/security/", "modules PAM"},
	{"/root/.ssh/", "accès SSH du compte root"},
}

// defaultUserDeniedPaths liste les préfixes refusés au scope user uniquement.
//
// Deux familles :
//   - tout ce qui est system-wide, qui relève exclusivement du scope machine ;
//   - à l'intérieur même du home, les fichiers qui gouvernent l'accès au compte
//     ou son environnement de connexion. Autoriser une GPO user à écrire
//     ~/.ssh/authorized_keys donnerait un accès SSH permanent au compte, et
//     ~/.profile permettrait d'exécuter n'importe quoi à chaque ouverture de
//     session — les deux contournent le catalogue de modules.
var defaultUserDeniedPaths = []string{
	"/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/boot/", "/dev/",
	"/proc/", "/sys/", "/var/", "/opt/", "/srv/", "/run/", "/root/",
	userHomePlaceholder + "/.ssh/",
	userHomePlaceholder + "/.profile",
	userHomePlaceholder + "/.bash_profile",
	userHomePlaceholder + "/.bash_login",
	userHomePlaceholder + "/.bashrc",
	userHomePlaceholder + "/.zshrc",
	userHomePlaceholder + "/.zprofile",
	userHomePlaceholder + "/.pam_environment",
}

// defaultUserAllowedPaths définit la zone d'écriture des GPO user : uniquement
// sous le marqueur de home. La présence d'au moins une autorisation transforme
// la validation en liste blanche pour ce scope.
var defaultUserAllowedPaths = []string{
	userHomePlaceholder + "/",
}

// defaultDeniedEnv liste les variables d'environnement interdites au départ :
// toutes permettent de détourner l'exécution d'un binaire quelconque.
var defaultDeniedEnv = []struct {
	Name string
	Note string
}{
	{"LD_PRELOAD", "injection de bibliothèque partagée"},
	{"LD_LIBRARY_PATH", "substitution de bibliothèque"},
	{"LD_AUDIT", "injection via l'interface d'audit du loader"},
	{"LD_ASSUME_KERNEL", "contournement de version de la glibc"},
	{"GCONV_PATH", "chargement de modules de conversion arbitraires"},
	{"PATH", "substitution de commandes"},
	{"IFS", "découpage de mots dans le shell"},
	{"BASH_ENV", "script exécuté au démarrage de bash non interactif"},
	{"ENV", "équivalent BASH_ENV pour sh"},
	{"SHELL", "changement d'interpréteur"},
	{"PROMPT_COMMAND", "commande exécutée à chaque invite"},
	{"PYTHONPATH", "substitution de module Python"},
	{"PYTHONSTARTUP", "script exécuté au lancement de l'interpréteur"},
	{"PERL5LIB", "substitution de module Perl"},
	{"NODE_OPTIONS", "injection d'options au démarrage de Node"},
	{"GIT_SSH", "commande SSH utilisée par git"},
	{"GIT_SSH_COMMAND", "commande SSH utilisée par git"},
	{"SSH_ASKPASS", "programme de saisie de mot de passe"},
	{"SUDO_ASKPASS", "programme de saisie de mot de passe sudo"},
	{"HOSTALIASES", "détournement de la résolution de noms"},
	{"NSS_WRAPPER_PASSWD", "détournement de la base de comptes"},
}

// seedDefinition est une définition à contenu écrite au premier démarrage.
type seedDefinition struct {
	Name    string
	Payload string
	Note    string
}

// dynamicFields associe chaque champ à domaine dynamique au module qui le porte.
// C'est la liste des champs dont les valeurs viennent de la base plutôt que du
// code, et donc ceux que l'interface Restrictions expose à l'édition.
//
// Un champ est soit une liste de noms simples (SeedValues), soit une liste de
// définitions porteuses d'un contenu (PayloadKind + SeedDefinitions) — voir
// payload.go pour ajouter un nouveau type de contenu.
var dynamicFields = []struct {
	ModuleType string
	FieldName  string
	Label      string
	// SeedValues est la liste initiale de noms simples.
	SeedValues []string
	// PayloadKind et SeedDefinitions sont utilisés pour les champs à contenu.
	PayloadKind     PayloadKind
	SeedDefinitions []seedDefinition
	// SeedMode, SeedAllowPattern et SeedDenyPattern sont la règle initiale.
	SeedMode         string
	SeedAllowPattern string
	SeedDenyPattern  string
	// Help décrit ce que l'entrée représente, affiché dans l'interface.
	Help string
}{
	{ModuleType: ModuleSystemdService, FieldName: "service", Label: "Unités systemd gérables",
		SeedValues: defaultServices, SeedMode: FieldModeList,
		Help: "Nom complet de l'unité, extension incluse (ex. mon-monitoring.service). Une fois l'unité ajoutée ici, le module GPO permet d'en choisir l'état comme pour n'importe quelle autre. Passez le champ en mode motif pour accepter toute une famille d'unités d'un coup."},
	{ModuleType: ModuleSysctl, FieldName: "key", Label: "Clés sysctl réglables",
		SeedValues: defaultSysctlKeys, SeedMode: FieldModeList,
		Help: "Clé sysctl en notation pointée (ex. net.ipv4.ip_forward). Ajoutez ici toute clé propre à votre parc."},
	{ModuleType: ModuleSysctl, FieldName: "value", Label: "Valeurs sysctl acceptées",
		SeedMode: FieldModePattern, SeedAllowPattern: defaultSysctlValuePattern,
		Help: "Contrôle la forme des valeurs sysctl. Par défaut un entier ou une liste d'entiers, ce qui couvre les clés de durcissement usuelles. Élargissez le motif si une clé custom attend une valeur textuelle."},
	{ModuleType: ModulePackage, FieldName: "package", Label: "Paquets gérables",
		SeedValues: defaultPackages, SeedMode: FieldModeList,
		Help: "Nom de paquet tel que le gestionnaire de la distribution l'attend. Ajoutez ici vos paquets internes ; le module gère ensuite présence, absence et version épinglée."},
	{ModuleType: ModuleSudoersRule, FieldName: "command_set", Label: "Jeux de commandes sudo",
		PayloadKind: PayloadCommandList, SeedDefinitions: sudoSeedDefinitions(), SeedMode: FieldModeList,
		Help: "Un jeu porte un nom et la liste des commandes qu'il autorise. C'est cette liste que l'agent rend dans le fichier /etc/sudoers.d/ généré : créer un jeu custom ne demande aucun code côté agent."},
	{ModuleType: ModuleUserCron, FieldName: "command_id", Label: "Tâches planifiables (user)",
		SeedValues: defaultCronCommandIDs, SeedMode: FieldModeList,
		Help: "Identifiant d'une commande implémentée côté agent client. Un identifiant sans implémentation donnera une tâche sans effet."},
}

// sudoSeedDefinitions convertit les jeux de commandes par défaut en définitions.
func sudoSeedDefinitions() []seedDefinition {
	out := make([]seedDefinition, 0, len(defaultSudoCommandSets))
	for _, s := range defaultSudoCommandSets {
		out = append(out, seedDefinition{Name: s.Name, Payload: s.Payload, Note: s.Note})
	}
	return out
}

// DynamicFieldDescriptor décrit un champ à domaine dynamique, pour l'interface
// d'administration et le peuplement initial.
type DynamicFieldDescriptor struct {
	ModuleType       string
	FieldName        string
	Label            string
	Help             string
	SeedValues       []string
	PayloadKind      PayloadKind
	SeedDefinitions  []DefinitionSeed
	SeedMode         string
	SeedAllowPattern string
	SeedDenyPattern  string
}

// DefinitionSeed est une définition initiale exposée hors du package.
type DefinitionSeed struct {
	Name    string
	Payload string
	Note    string
}

// HasPayload indique si le champ porte des définitions à contenu.
func (d DynamicFieldDescriptor) HasPayload() bool { return d.PayloadKind != PayloadNone }

// ModuleLabelFor retourne le libellé du module portant ce champ.
func (d DynamicFieldDescriptor) ModuleLabelFor() string { return ModuleLabel(d.ModuleType) }

// Key retourne la clé d'indexation du champ.
func (d DynamicFieldDescriptor) Key() string { return FieldKey(d.ModuleType, d.FieldName) }

// DynamicFields retourne les champs dont le domaine de valeurs vit en base.
func DynamicFields() []DynamicFieldDescriptor {
	out := make([]DynamicFieldDescriptor, 0, len(dynamicFields))
	for _, f := range dynamicFields {
		defs := make([]DefinitionSeed, 0, len(f.SeedDefinitions))
		for _, d := range f.SeedDefinitions {
			defs = append(defs, DefinitionSeed{Name: d.Name, Payload: d.Payload, Note: d.Note})
		}
		out = append(out, DynamicFieldDescriptor{
			ModuleType: f.ModuleType, FieldName: f.FieldName, Label: f.Label,
			Help: f.Help, SeedValues: append([]string(nil), f.SeedValues...),
			PayloadKind: f.PayloadKind, SeedDefinitions: defs,
			SeedMode: f.SeedMode, SeedAllowPattern: f.SeedAllowPattern,
			SeedDenyPattern: f.SeedDenyPattern,
		})
	}
	return out
}

// IsDynamicField indique si les valeurs d'un champ viennent de la base.
func IsDynamicField(moduleType, fieldName string) bool {
	for _, f := range dynamicFields {
		if f.ModuleType == moduleType && f.FieldName == fieldName {
			return true
		}
	}
	return false
}

// DefaultRestrictions construit le jeu de restrictions par défaut.
func DefaultRestrictions() RestrictionSet {
	rs := RestrictionSet{
		AllowedValues: map[string][]AllowedValue{},
		Definitions:   map[string][]ValueDefinition{},
		FieldRules:    map[string]FieldRule{},
	}

	for _, f := range dynamicFields {
		key := FieldKey(f.ModuleType, f.FieldName)
		entries := make([]AllowedValue, 0, len(f.SeedValues))
		for _, v := range f.SeedValues {
			entries = append(entries, AllowedValue{
				ModuleType: f.ModuleType, FieldName: f.FieldName, Value: v,
			})
		}
		rs.AllowedValues[key] = entries

		defs := make([]ValueDefinition, 0, len(f.SeedDefinitions))
		for _, d := range f.SeedDefinitions {
			defs = append(defs, ValueDefinition{
				ModuleType: f.ModuleType, FieldName: f.FieldName, Name: d.Name,
				Kind: f.PayloadKind, Payload: d.Payload, Note: d.Note,
			})
		}
		rs.Definitions[key] = defs

		mode := f.SeedMode
		if !IsValidFieldMode(mode) {
			mode = FieldModeList
		}
		rs.FieldRules[key] = FieldRule{
			ModuleType: f.ModuleType, FieldName: f.FieldName, Mode: mode,
			AllowPattern: f.SeedAllowPattern, DenyPattern: f.SeedDenyPattern,
			Note: f.Help,
		}
	}

	for _, p := range defaultDeniedPaths {
		rs.PathRules = append(rs.PathRules, PathRule{
			Scope: PathScopeAny, Deny: true, Prefix: p.Prefix, Note: p.Note,
		})
	}
	for _, p := range defaultUserDeniedPaths {
		rs.PathRules = append(rs.PathRules, PathRule{
			Scope: string(ScopeUser), Deny: true, Prefix: p,
			Note: "hors du home : relève du scope machine",
		})
	}
	for _, p := range defaultUserAllowedPaths {
		rs.PathRules = append(rs.PathRules, PathRule{
			Scope: string(ScopeUser), Deny: false, Prefix: p,
			Note: "zone d'écriture des GPO utilisateur",
		})
	}

	for _, e := range defaultDeniedEnv {
		rs.EnvDenied = append(rs.EnvDenied, EnvRule{Name: e.Name, Note: e.Note})
	}

	return rs
}

// DefaultPathRules expose les règles de chemin par défaut, pour le peuplement
// initial et la fonction de réinitialisation.
func DefaultPathRules() []PathRule { return DefaultRestrictions().PathRules }

// DefaultEnvRules expose les variables interdites par défaut.
func DefaultEnvRules() []EnvRule { return DefaultRestrictions().EnvDenied }
