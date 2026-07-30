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

// defaultSudoCommandSets liste les jeux de commandes sudo attribuables au départ.
// Chaque identifiant correspond à un template rendu côté agent client : ajouter
// une entrée ici sans implémentation côté agent donnera un module sans effet.
var defaultSudoCommandSets = []string{
	"ALL", "pkg_management", "service_control", "network_diagnostics", "log_read", "disk_read",
}

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

// SSHDirectiveField est la clé de champ virtuelle qui contrôle les directives
// sshd acceptées dans le champ « Directives supplémentaires ». Ce n'est pas un
// champ de formulaire : c'est une règle appliquée ligne à ligne au contenu du
// champ extra_directives, ce qui permet au superadmin d'ouvrir ou de fermer des
// directives sans changer le code.
const SSHDirectiveField = "directive"

// defaultSSHDirectiveDeny refuse les directives sshd qui permettraient une
// exécution de code en root, ainsi que celles déjà pilotées par un champ dédié
// du module (les régler deux fois donnerait un résultat dépendant de l'ordre).
const defaultSSHDirectiveDeny = `^(?i)(Include|AuthorizedKeysCommand|AuthorizedKeysCommandUser|` +
	`AuthorizedPrincipalsCommand|AuthorizedPrincipalsCommandUser|ForceCommand|Subsystem|` +
	`ChrootDirectory|Match|SetEnv|AcceptEnv|PermitUserEnvironment|PermitRootLogin|` +
	`PasswordAuthentication|PubkeyAuthentication|AllowTcpForwarding|X11Forwarding|` +
	`MaxAuthTries|ClientAliveInterval|Banner)$`

// defaultSSHDirectiveAllow n'accepte qu'un mot-clé sshd bien formé.
const defaultSSHDirectiveAllow = `^[A-Za-z][A-Za-z0-9]{1,40}$`

// dynamicFields associe chaque champ à domaine dynamique au module qui le porte.
// C'est la liste des champs dont les valeurs viennent de la base plutôt que du
// code, et donc ceux que l'interface Restrictions expose à l'édition.
var dynamicFields = []struct {
	ModuleType string
	FieldName  string
	Label      string
	// SeedValues est la liste initiale écrite en base au premier démarrage.
	SeedValues []string
	// SeedMode, SeedAllowPattern et SeedDenyPattern sont la règle initiale.
	SeedMode         string
	SeedAllowPattern string
	SeedDenyPattern  string
	// Help décrit ce que l'entrée représente, affiché dans l'interface.
	Help string
}{
	{ModuleType: ModuleSystemdService, FieldName: "service", Label: "Unités systemd gérables",
		SeedValues: defaultServices, SeedMode: FieldModeList,
		Help: "Nom complet de l'unité, extension incluse (ex. mon-monitoring.service). Passez ce champ en mode motif pour accepter toute une famille d'unités d'un coup."},
	{ModuleType: ModuleSysctl, FieldName: "key", Label: "Clés sysctl réglables",
		SeedValues: defaultSysctlKeys, SeedMode: FieldModeList,
		Help: "Clé sysctl en notation pointée (ex. net.ipv4.ip_forward)."},
	{ModuleType: ModulePackage, FieldName: "package", Label: "Paquets gérables",
		SeedValues: defaultPackages, SeedMode: FieldModeList,
		Help: "Nom de paquet tel que le gestionnaire de la distribution l'attend."},
	{ModuleType: ModuleSudoersRule, FieldName: "command_set", Label: "Jeux de commandes sudo",
		SeedValues: defaultSudoCommandSets, SeedMode: FieldModeList,
		Help: "Identifiant d'un template sudoers implémenté côté agent client. Un identifiant sans implémentation donnera un module sans effet."},
	{ModuleType: ModuleUserCron, FieldName: "command_id", Label: "Tâches planifiables (user)",
		SeedValues: defaultCronCommandIDs, SeedMode: FieldModeList,
		Help: "Identifiant d'une commande implémentée côté agent client."},
	{ModuleType: ModuleSSHServerConfig, FieldName: SSHDirectiveField, Label: "Directives sshd acceptées",
		SeedMode: FieldModePattern, SeedAllowPattern: defaultSSHDirectiveAllow,
		SeedDenyPattern: defaultSSHDirectiveDeny,
		Help: "Contrôle les mots-clés utilisables dans « Directives supplémentaires » du module SSH. En mode motif par défaut : tout mot-clé bien formé est accepté, sauf ceux du motif d'exclusion (exécution de code, ou déjà pilotés par un champ dédié)."},
}

// DynamicFieldDescriptor décrit un champ à domaine dynamique, pour l'interface
// d'administration et le peuplement initial.
type DynamicFieldDescriptor struct {
	ModuleType       string
	FieldName        string
	Label            string
	Help             string
	SeedValues       []string
	SeedMode         string
	SeedAllowPattern string
	SeedDenyPattern  string
}

// ModuleLabelFor retourne le libellé du module portant ce champ.
func (d DynamicFieldDescriptor) ModuleLabelFor() string { return ModuleLabel(d.ModuleType) }

// Key retourne la clé d'indexation du champ.
func (d DynamicFieldDescriptor) Key() string { return FieldKey(d.ModuleType, d.FieldName) }

// DynamicFields retourne les champs dont le domaine de valeurs vit en base.
func DynamicFields() []DynamicFieldDescriptor {
	out := make([]DynamicFieldDescriptor, 0, len(dynamicFields))
	for _, f := range dynamicFields {
		out = append(out, DynamicFieldDescriptor{
			ModuleType: f.ModuleType, FieldName: f.FieldName, Label: f.Label,
			Help: f.Help, SeedValues: append([]string(nil), f.SeedValues...),
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
