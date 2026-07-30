package gpo

import (
	"fmt"
	"os"
	"strings"
)

// Appliqueurs des modules de scope machine.
//
// Règle commune : Vaultaire écrit dans des fichiers qui lui appartiennent
// (fragments dédiés en .d/), jamais dans les fichiers principaux de la
// distribution. Un administrateur doit pouvoir retirer Vaultaire en supprimant
// ses fragments, sans avoir à réparer sshd_config ou sysctl.conf à la main.

const (
	sshFragmentPath = "/etc/ssh/sshd_config.d/99-vaultaire-gpo.conf"
	sshBannerPath   = "/etc/ssh/vaultaire-banner"
	sysctlDir       = "/etc/sysctl.d"
	sudoersDir      = "/etc/sudoers.d"
)

// applySSHServerConfig écrit le fragment sshd et recharge le service.
//
// La configuration est validée par `sshd -t` AVANT rechargement, et le fragment
// précédent est restauré en cas d'échec. Sans ce retour arrière, une directive
// invalide poussée sur le parc empêcherait sshd de redémarrer et couperait
// l'accès à toutes les machines — sans moyen d'y revenir.
func applySSHServerConfig(ctx Context, m Module) (string, error) {
	var directives []string

	simple := []struct{ param, keyword string }{
		{"permit_root_login", "PermitRootLogin"},
		{"password_authentication", "PasswordAuthentication"},
		{"pubkey_authentication", "PubkeyAuthentication"},
		{"allow_tcp_forwarding", "AllowTcpForwarding"},
		{"x11_forwarding", "X11Forwarding"},
	}
	for _, s := range simple {
		value := m.Param(s.param)
		if value == "" || value == "unchanged" {
			continue
		}
		directives = append(directives, s.keyword+" "+value)
	}
	for _, s := range []struct{ param, keyword string }{
		{"max_auth_tries", "MaxAuthTries"},
		{"client_alive_interval", "ClientAliveInterval"},
	} {
		if value := m.Param(s.param); value != "" {
			directives = append(directives, s.keyword+" "+value)
		}
	}

	banner := m.RawParam("banner_text")
	if strings.TrimSpace(banner) != "" {
		if err := writeSystemFile(sshBannerPath, banner, 0o644); err != nil {
			return "", fmt.Errorf("banniere SSH : %v", err)
		}
		directives = append(directives, "Banner "+sshBannerPath)
	}

	if len(directives) == 0 {
		return "", fmt.Errorf("aucune directive a ecrire")
	}

	previous, hadPrevious := readFileIfExists(sshFragmentPath)
	content := "# Fichier genere par Vaultaire GPO. Ne pas editer a la main.\n" +
		strings.Join(directives, "\n") + "\n"

	if err := writeSystemFile(sshFragmentPath, content, 0o644); err != nil {
		return "", err
	}

	if commandExists("sshd") {
		if _, err := runCommand("sshd", "-t"); err != nil {
			restoreOrRemove(sshFragmentPath, previous, hadPrevious)
			return "", fmt.Errorf("configuration sshd refusee, fragment precedent restaure : %v", err)
		}
	}

	if commandExists("systemctl") {
		if _, err := runCommand("systemctl", "reload", "sshd"); err != nil {
			// Certaines distributions nomment l'unité « ssh ».
			if _, errAlt := runCommand("systemctl", "reload", "ssh"); errAlt != nil {
				restoreOrRemove(sshFragmentPath, previous, hadPrevious)
				return "", fmt.Errorf("rechargement sshd impossible, fragment precedent restaure : %v", err)
			}
		}
	}

	return fmt.Sprintf("%d directive(s) ecrite(s) dans %s", len(directives), sshFragmentPath), nil
}

// applySysctl écrit une clé sysctl dans un fichier dédié et l'applique à chaud.
func applySysctl(ctx Context, m Module) (string, error) {
	key := m.Param("key")
	value := m.Param("value")
	if key == "" || value == "" {
		return "", fmt.Errorf("cle ou valeur sysctl manquante")
	}

	// Un fichier par clé : retirer une clé de la politique revient à supprimer
	// son fichier, sans avoir à réécrire un fichier partagé.
	path := fmt.Sprintf("%s/90-vaultaire-%s.conf", sysctlDir, strings.ReplaceAll(key, "/", "_"))
	content := "# Genere par Vaultaire GPO\n" + key + " = " + value + "\n"

	if err := writeSystemFile(path, content, 0o644); err != nil {
		return "", err
	}

	if commandExists("sysctl") {
		if _, err := runCommand("sysctl", "-w", key+"="+value); err != nil {
			// L'écriture persistante a réussi : la valeur sera prise au prochain
			// démarrage même si l'application à chaud échoue (clé absente du
			// noyau courant, espace de noms restreint en conteneur).
			return "", fmt.Errorf("valeur ecrite dans %s mais application a chaud refusee : %v", path, err)
		}
	}
	return fmt.Sprintf("%s = %s (%s)", key, value, path), nil
}

// applySudoersRule génère un fichier sudoers depuis un template contrôlé.
//
// Le contenu du jeu de commandes n'est pas transmis dans le module : le module
// ne porte que son nom. L'agent ne peut donc pas écrire une règle sudoers
// arbitraire, même si la politique était forgée.
func applySudoersRule(ctx Context, m Module) (string, error) {
	group := m.Param("group")
	commandSet := m.Param("command_set")
	if group == "" || commandSet == "" {
		return "", fmt.Errorf("groupe ou jeu de commandes manquant")
	}

	commands, err := sudoCommandsFor(commandSet)
	if err != nil {
		return "", err
	}

	tag := ""
	if m.BoolParam("nopasswd") {
		tag = "NOPASSWD: "
	}

	path := fmt.Sprintf("%s/90-vaultaire-%s", sudoersDir, group)
	content := fmt.Sprintf(
		"# Genere par Vaultaire GPO — jeu de commandes %q\n%%%s ALL=(ALL) %s%s\n",
		commandSet, group, tag, strings.Join(commands, ", "))

	previous, hadPrevious := readFileIfExists(path)
	if err := writeSystemFile(path, content, 0o440); err != nil {
		return "", err
	}

	// visudo valide la syntaxe avant que le fichier ne soit pris en compte. Un
	// sudoers invalide casse sudo pour toute la machine, y compris pour réparer.
	if commandExists("visudo") {
		if _, err := runCommand("visudo", "-cf", path); err != nil {
			restoreOrRemove(path, previous, hadPrevious)
			return "", fmt.Errorf("regle sudoers refusee, etat precedent restaure : %v", err)
		}
	}

	return fmt.Sprintf("groupe %s : %s (%d commande(s))", group, commandSet, len(commands)), nil
}

// sudoCommandsFor traduit un identifiant de jeu de commandes en liste concrète.
//
// Les jeux vivent côté serveur dans gpo_value_definition, mais l'agent ne reçoit
// que leur nom : il faut donc que l'implémentation existe ici. Un jeu créé côté
// serveur sans correspondance ici est rapporté en échec explicite, ce qui rend
// le défaut visible dans l'interface au lieu de produire un sudoers vide.
func sudoCommandsFor(name string) ([]string, error) {
	sets := map[string][]string{
		"ALL": {"ALL"},
		"pkg_management": {
			"/usr/bin/apt-get", "/usr/bin/apt", "/usr/bin/dnf", "/usr/bin/yum",
			"/usr/bin/rpm", "/usr/bin/dpkg",
		},
		"service_control": {
			"/usr/bin/systemctl start", "/usr/bin/systemctl stop",
			"/usr/bin/systemctl restart", "/usr/bin/systemctl reload",
			"/usr/bin/systemctl status",
		},
		"network_diagnostics": {
			"/usr/bin/ping", "/usr/sbin/ip", "/usr/bin/ss",
			"/usr/sbin/tcpdump", "/usr/bin/traceroute", "/usr/bin/dig",
		},
		"log_read":  {"/usr/bin/journalctl", "/usr/bin/dmesg", "/usr/bin/tail", "/usr/bin/less"},
		"disk_read": {"/usr/bin/df", "/usr/bin/du", "/usr/sbin/blkid", "/usr/bin/lsblk", "/usr/bin/smartctl"},
	}
	commands, ok := sets[name]
	if !ok {
		return nil, fmt.Errorf(
			"jeu de commandes %q inconnu de cet agent : il existe cote serveur mais pas son implementation locale", name)
	}
	return commands, nil
}

// applyPackage installe ou retire un paquet.
func applyPackage(ctx Context, m Module) (string, error) {
	pkg := m.Param("package")
	state := m.Param("state")
	version := m.Param("version")
	if pkg == "" {
		return "", fmt.Errorf("nom de paquet manquant")
	}

	manager, err := detectPackageManager()
	if err != nil {
		return "", err
	}

	target := pkg
	if version != "" && state == "present" {
		if manager == "apt-get" {
			target = pkg + "=" + version
		} else {
			target = pkg + "-" + version
		}
	}

	var args []string
	switch {
	case state == "absent" && manager == "apt-get":
		args = []string{"-y", "remove", pkg}
	case state == "absent":
		args = []string{"-y", "remove", pkg}
	case manager == "apt-get":
		args = []string{"-y", "install", target}
	default:
		args = []string{"-y", "install", target}
	}

	env := ""
	if manager == "apt-get" {
		// apt refuse d'agir sans terminal si une question se présente ; le mode
		// non interactif évite un blocage indéfini au démarrage de la machine.
		env = "DEBIAN_FRONTEND=noninteractive"
		os.Setenv("DEBIAN_FRONTEND", "noninteractive")
	}

	if _, err := runCommand(manager, args...); err != nil {
		return "", err
	}
	detail := fmt.Sprintf("%s %s via %s", state, target, manager)
	if env != "" {
		detail += " (non interactif)"
	}
	return detail, nil
}

// detectPackageManager identifie le gestionnaire de paquets disponible.
func detectPackageManager() (string, error) {
	for _, candidate := range []string{"apt-get", "dnf", "yum", "zypper"} {
		if commandExists(candidate) {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("aucun gestionnaire de paquets reconnu sur cette machine")
}

// applySystemdService force l'état d'une unité systemd.
//
// L'ordre des opérations compte : démasquer d'abord (une unité masquée refuse
// toute autre commande), puis activer, puis agir sur l'état courant, et masquer
// en dernier.
func applySystemdService(ctx Context, m Module) (string, error) {
	service := m.Param("service")
	if service == "" {
		return "", fmt.Errorf("nom d'unite manquant")
	}
	if !commandExists("systemctl") {
		return "", fmt.Errorf("systemctl absent de cette machine")
	}

	masked := m.BoolParam("masked")
	enabled := m.Param("enabled")
	state := m.Param("state")
	var actions []string

	if !masked {
		// Sans effet si l'unité n'est pas masquée : on ignore l'échec éventuel.
		if _, err := runCommand("systemctl", "unmask", service); err == nil {
			actions = append(actions, "unmask")
		}
	}

	switch enabled {
	case "enabled":
		if _, err := runCommand("systemctl", "enable", service); err != nil {
			return "", err
		}
		actions = append(actions, "enable")
	case "disabled":
		if _, err := runCommand("systemctl", "disable", service); err != nil {
			return "", err
		}
		actions = append(actions, "disable")
	}

	switch state {
	case "started":
		if _, err := runCommand("systemctl", "start", service); err != nil {
			return "", err
		}
		actions = append(actions, "start")
	case "stopped":
		if _, err := runCommand("systemctl", "stop", service); err != nil {
			return "", err
		}
		actions = append(actions, "stop")
	case "restarted":
		if _, err := runCommand("systemctl", "restart", service); err != nil {
			return "", err
		}
		actions = append(actions, "restart")
	}

	if masked {
		if _, err := runCommand("systemctl", "mask", service); err != nil {
			return "", err
		}
		actions = append(actions, "mask")
	}

	if len(actions) == 0 {
		return service + " : aucun changement demande", nil
	}
	return fmt.Sprintf("%s : %s", service, strings.Join(actions, ", ")), nil
}

// ---------------------------------------------------------------------------
// Utilitaires fichiers système
// ---------------------------------------------------------------------------

// writeSystemFile écrit un fichier système de façon atomique.
func writeSystemFile(path, content string, mode os.FileMode) error {
	dir := path[:strings.LastIndex(path, "/")]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creation de %s impossible : %v", dir, err)
	}

	tmp, err := os.CreateTemp(dir, ".vaultaire-*.tmp")
	if err != nil {
		return fmt.Errorf("fichier temporaire dans %s impossible : %v", dir, err)
	}
	tmpName := tmp.Name()

	fail := func(format string, args ...interface{}) error {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf(format, args...)
	}

	if _, err := tmp.WriteString(content); err != nil {
		return fail("ecriture de %s impossible : %v", path, err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("synchronisation de %s impossible : %v", path, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("fermeture de %s impossible : %v", path, err)
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("permissions de %s impossibles : %v", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("remplacement de %s impossible : %v", path, err)
	}
	return nil
}

// readFileIfExists lit un fichier s'il existe.
func readFileIfExists(path string) (string, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// restoreOrRemove remet un fichier dans son état antérieur.
func restoreOrRemove(path, previous string, hadPrevious bool) {
	if hadPrevious {
		_ = writeSystemFile(path, previous, 0o644)
		return
	}
	_ = os.Remove(path)
}
