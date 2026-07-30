package gpo

import (
	"fmt"
	"path"
	"strings"
)

// Ce fichier contient les garde-fous non négociables du système de GPO.
//
// Règle : toute liste définie ici est codée en dur, jamais alimentée depuis la
// base ni depuis une requête. Une GPO authentifiée et signée par le serveur
// central reste soumise à ces limites. Elles existent pour qu'un serveur
// compromis ou un compte admin détourné ne puisse pas transformer le mécanisme
// de GPO en primitive d'élévation de privilège.

// protectedPathPrefixes liste les chemins qu'AUCUNE GPO ne peut écrire, quel
// que soit son scope. Ce sont les fichiers qui décident eux-mêmes de qui a des
// privilèges, plus l'état local de l'agent Vaultaire : les laisser modifiables
// rendrait la sécurité du reste décorative.
var protectedPathPrefixes = []string{
	"/etc/pam.d/",
	"/etc/security/",
	"/etc/sudoers",
	"/etc/sudoers.d/",
	"/etc/shadow",
	"/etc/gshadow",
	"/etc/passwd",
	"/etc/group",
	"/etc/ssh/sshd_config",
	"/etc/ssh/ssh_host_",
	"/etc/vaultaire/",
	"/var/lib/vaultaire/",
	"/lib/security/",
	"/lib64/security/",
	"/usr/lib/security/",
	"/usr/lib64/security/",
	"/root/.ssh/",
}

// userForbiddenPathPrefixes liste les préfixes interdits en scope user, en plus
// des chemins protégés globalement. Un module user ne doit écrire que sous le
// home de l'utilisateur cible : tout ce qui est system-wide relève
// exclusivement du scope machine.
var userForbiddenPathPrefixes = []string{
	"/etc/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/",
	"/boot/", "/dev/", "/proc/", "/sys/", "/var/", "/opt/", "/srv/", "/run/",
	"/root/",
}

// forbiddenEnvNames liste les variables d'environnement qu'une GPO user ne peut
// pas définir : elles permettent de détourner l'exécution de n'importe quel
// binaire (injection de bibliothèque, substitution d'interpréteur, redirection
// de la résolution de commandes).
var forbiddenEnvNames = map[string]bool{
	"LD_PRELOAD":         true,
	"LD_LIBRARY_PATH":    true,
	"LD_AUDIT":           true,
	"PATH":               true,
	"IFS":                true,
	"BASH_ENV":           true,
	"ENV":                true,
	"SHELL":              true,
	"PYTHONPATH":         true,
	"PYTHONSTARTUP":      true,
	"PERL5LIB":           true,
	"NODE_OPTIONS":       true,
	"GIT_SSH":            true,
	"GIT_SSH_COMMAND":    true,
	"SSH_ASKPASS":        true,
	"SUDO_ASKPASS":       true,
	"PROMPT_COMMAND":     true,
	"LD_ASSUME_KERNEL":   true,
	"GCONV_PATH":         true,
	"HOSTALIASES":        true,
	"NSS_WRAPPER_PASSWD": true,
}

// allowedServices liste les unités systemd gérables par GPO. Volontairement
// restreinte : autoriser un nom d'unité arbitraire permettrait de démasquer ou
// relancer un service critique (ou d'arrêter sshd et de couper l'accès au parc).
var allowedServices = []string{
	"apparmor.service",
	"auditd.service",
	"avahi-daemon.service",
	"avahi-daemon.socket",
	"chronyd.service",
	"cups.service",
	"cups.socket",
	"firewalld.service",
	"nftables.service",
	"nfs-server.service",
	"ntp.service",
	"rpcbind.service",
	"rpcbind.socket",
	"rsyslog.service",
	"smbd.service",
	"snapd.service",
	"systemd-timesyncd.service",
	"telnet.socket",
	"tftp.socket",
	"vsftpd.service",
}

// allowedSysctlKeys liste les clés sysctl réglables par GPO. Restreinte aux
// paramètres de durcissement réseau et noyau : d'autres clés (notamment
// kernel.modprobe, kernel.core_pattern) sont des vecteurs d'exécution de code.
var allowedSysctlKeys = []string{
	"kernel.dmesg_restrict",
	"kernel.kptr_restrict",
	"kernel.randomize_va_space",
	"kernel.sysrq",
	"kernel.unprivileged_bpf_disabled",
	"kernel.yama.ptrace_scope",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv4.conf.all.accept_source_route",
	"net.ipv4.conf.all.log_martians",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.icmp_echo_ignore_broadcasts",
	"net.ipv4.ip_forward",
	"net.ipv4.tcp_syncookies",
	"net.ipv6.conf.all.accept_ra",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv6.conf.all.disable_ipv6",
	"vm.mmap_min_addr",
	"vm.swappiness",
}

// allowedPackages liste les paquets dont la présence ou l'absence peut être
// imposée. Un nom de paquet arbitraire exécuterait des scripts post-install
// non vérifiés en root : c'est de l'exécution de code déguisée.
var allowedPackages = []string{
	"aide",
	"auditd",
	"chrony",
	"cups",
	"curl",
	"fail2ban",
	"git",
	"htop",
	"nftables",
	"rsh-client",
	"rsync",
	"telnet",
	"tmux",
	"unzip",
	"vim",
	"vsftpd",
	"xinetd",
	"zsh",
}

// allowedSudoCommandSets liste les jeux de commandes attribuables via
// sudoers_rule. Le module ne prend jamais de ligne sudoers brute : l'agent
// client rend un template à partir de cet identifiant, ce qui interdit
// l'injection de directives (Defaults!, NOPASSWD global, etc.).
var allowedSudoCommandSets = []string{
	"ALL",
	"pkg_management",
	"service_control",
	"network_diagnostics",
	"log_read",
	"disk_read",
}

// allowedCronCommandIDs liste les tâches planifiables en scope user. La GPO
// référence un identifiant, jamais une ligne de shell : c'est l'agent client
// qui détient l'implémentation correspondante.
var allowedCronCommandIDs = []string{
	"backup_home",
	"cleanup_tmp",
	"report_disk_usage",
	"sync_dotfiles",
	"rotate_user_logs",
}

// AllowedServices retourne la liste des unités systemd gérables.
func AllowedServices() []string { return append([]string(nil), allowedServices...) }

// AllowedSysctlKeys retourne la liste des clés sysctl réglables.
func AllowedSysctlKeys() []string { return append([]string(nil), allowedSysctlKeys...) }

// AllowedPackages retourne la liste des paquets gérables.
func AllowedPackages() []string { return append([]string(nil), allowedPackages...) }

// AllowedSudoCommandSets retourne les jeux de commandes sudo attribuables.
func AllowedSudoCommandSets() []string { return append([]string(nil), allowedSudoCommandSets...) }

// AllowedCronCommandIDs retourne les tâches planifiables en scope user.
func AllowedCronCommandIDs() []string { return append([]string(nil), allowedCronCommandIDs...) }

// ProtectedPathPrefixes retourne les préfixes interdits à toutes les GPO.
func ProtectedPathPrefixes() []string { return append([]string(nil), protectedPathPrefixes...) }

// UserForbiddenPathPrefixes retourne les préfixes interdits en scope user.
func UserForbiddenPathPrefixes() []string {
	return append([]string(nil), userForbiddenPathPrefixes...)
}

// IsForbiddenEnvName indique si une variable d'environnement est interdite.
func IsForbiddenEnvName(name string) bool {
	return forbiddenEnvNames[strings.ToUpper(strings.TrimSpace(name))]
}

// CheckPath valide un chemin de fichier pour un scope donné.
//
// Il refuse : les chemins relatifs, la traversée (..), les chemins protégés
// globalement, et — en scope user — tout ce qui sort du home de l'utilisateur.
func CheckPath(p string, scope Scope) error {
	raw := strings.TrimSpace(p)
	if raw == "" {
		return fmt.Errorf("chemin vide")
	}
	if strings.ContainsAny(raw, "\x00\n\r") {
		return fmt.Errorf("chemin contenant un caractère de contrôle")
	}
	if !strings.HasPrefix(raw, "/") {
		return fmt.Errorf("chemin non absolu : %s", raw)
	}
	clean := path.Clean(raw)
	if clean != raw && clean+"/" != raw {
		return fmt.Errorf("chemin non canonique (traversée ou doublon de séparateur) : %s", raw)
	}
	if strings.Contains(clean, "/../") || strings.HasSuffix(clean, "/..") {
		return fmt.Errorf("traversée de répertoire interdite : %s", raw)
	}

	lower := strings.ToLower(clean)
	for _, prefix := range protectedPathPrefixes {
		if lower == strings.TrimSuffix(strings.ToLower(prefix), "/") || strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return fmt.Errorf("chemin protégé, non modifiable par GPO : %s", clean)
		}
	}

	if scope == ScopeUser {
		if !isUserWritablePath(clean) {
			return fmt.Errorf("une GPO user ne peut écrire que sous le home de l'utilisateur (utilisez %%h/...) : %s", clean)
		}
	}
	return nil
}

// userHomePlaceholder est le marqueur substitué par l'agent client par le home
// réel de l'utilisateur cible. Il évite d'écrire des chemins absolus vers
// /home/<user>, qui seraient valides pour un utilisateur et faux pour un autre.
const userHomePlaceholder = "/%h"

// isUserWritablePath n'autorise, en scope user, que les chemins exprimés
// relativement au home via le marqueur %h.
func isUserWritablePath(clean string) bool {
	if clean == userHomePlaceholder {
		return false
	}
	if !strings.HasPrefix(clean, userHomePlaceholder+"/") {
		return false
	}
	// Refus explicite des sous-chemins qui redonneraient un accès privilégié
	// en détournant l'environnement de connexion de l'utilisateur.
	rest := strings.ToLower(strings.TrimPrefix(clean, userHomePlaceholder+"/"))
	for _, forbidden := range []string{".ssh/", ".profile", ".bash_profile", ".bash_login", ".pam_environment"} {
		if rest == strings.TrimSuffix(forbidden, "/") || strings.HasPrefix(rest, forbidden) {
			return false
		}
	}
	return true
}

// UserHomePlaceholder expose le marqueur de home pour l'interface web.
func UserHomePlaceholder() string { return userHomePlaceholder }

// CheckModuleScope applique le garde-fou anti-élévation de privilège : un
// module réservé au scope machine ne peut jamais apparaître dans une GPO user,
// même si la GPO provient du serveur central authentifié.
func CheckModuleScope(moduleType string, policyScope Scope) error {
	schema, ok := SchemaFor(moduleType)
	if !ok {
		return fmt.Errorf("module inconnu : %s", moduleType)
	}
	if !schema.AllowedInScope(policyScope) {
		return fmt.Errorf("le module %s est réservé au scope %s et ne peut pas figurer dans une GPO %s",
			moduleType, schema.Scope, policyScope)
	}
	return nil
}

// MachineOnlyModuleTypes retourne les types de modules réservés au scope
// machine. Cette liste est dérivée du catalogue, donc toujours cohérente avec
// lui : ajouter un module machine-only au registre suffit à l'interdire côté user.
func MachineOnlyModuleTypes() []string {
	var out []string
	for _, s := range Catalog() {
		if s.Scope == ScopeMachine {
			out = append(out, s.Type)
		}
	}
	return out
}
