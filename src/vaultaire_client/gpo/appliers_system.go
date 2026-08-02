package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Appliqueurs système — phase de configuration, et ménage en fin de cycle.

// ---------------------------------------------------------------------------
// Paramètres noyau au démarrage (boot_params)
// ---------------------------------------------------------------------------

const grubDropIn = "/etc/default/grub.d/99-vaultaire-gpo.cfg"

// applyBootParams ajoute ou retire un paramètre de la ligne de commande noyau.
//
// GRUB est le seul module du catalogue dont une erreur empêche la machine de
// DÉMARRER. La configuration générée est donc validée avant d'être installée,
// et l'état précédent restauré si la génération échoue. Un paramètre accepté par
// GRUB mais refusé par le noyau reste possible : c'est la limite de ce qu'on
// peut vérifier sans redémarrer.
func applyBootParams(ctx Context, m Module) (string, error) {
	param := m.Param("parameter")
	if param == "" {
		return "", fmt.Errorf("parametre manquant")
	}
	if strings.ContainsAny(param, "\"'`$;&|\n") {
		// Le paramètre finit dans une variable shell lue par les scripts GRUB :
		// un guillemet ou un point-virgule y ferait sortir de la chaîne.
		return "", fmt.Errorf("parametre %q : caracteres non autorises", param)
	}

	previous, had := readFileIfExists(grubDropIn)
	params := parseGrubParams(previous)

	key := strings.SplitN(param, "=", 2)[0]
	// Un paramètre est remplacé et non dupliqué : « audit=0 » puis « audit=1 »
	// doit donner une seule valeur, sinon le noyau retient la dernière et la
	// configuration devient illisible.
	var kept []string
	for _, existing := range params {
		if strings.SplitN(existing, "=", 2)[0] != key {
			kept = append(kept, existing)
		}
	}
	if m.Param("state") != "absent" {
		kept = append(kept, param)
	}

	if len(kept) == 0 {
		if err := os.Remove(grubDropIn); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		if err := regenerateGrub(); err != nil {
			restoreOrRemove(grubDropIn, previous, had)
			_ = regenerateGrub()
			return "", fmt.Errorf("regeneration GRUB impossible, etat precedent restaure : %v", err)
		}
		return "parametre " + param + " retire (aucun parametre Vaultaire restant)", nil
	}

	content := "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
		`GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT ` + strings.Join(kept, " ") + `"` + "\n"
	if err := writeSystemFile(grubDropIn, content, 0o644); err != nil {
		return "", err
	}
	if err := regenerateGrub(); err != nil {
		restoreOrRemove(grubDropIn, previous, had)
		_ = regenerateGrub()
		return "", fmt.Errorf("regeneration GRUB impossible, etat precedent restaure : %v", err)
	}

	action := "ajoute"
	if m.Param("state") == "absent" {
		action = "retire"
	}
	return "parametre " + param + " " + action + " (effectif au prochain redemarrage)", nil
}

// parseGrubParams extrait les paramètres déjà posés par Vaultaire.
func parseGrubParams(content string) []string {
	for _, line := range strings.Split(content, "\n") {
		if !strings.HasPrefix(line, "GRUB_CMDLINE_LINUX_DEFAULT=") {
			continue
		}
		inner := line[strings.Index(line, "=")+1:]
		inner = strings.Trim(inner, `"`)
		inner = strings.TrimPrefix(inner, "$GRUB_CMDLINE_LINUX_DEFAULT")
		return strings.Fields(inner)
	}
	return nil
}

// regenerateGrub régénère la configuration de démarrage.
//
// La sortie part vers /dev/null : on ne cherche pas à installer la
// configuration ici, seulement à vérifier qu'elle se génère. L'installation
// réelle est faite ensuite par la commande propre à la distribution.
func regenerateGrub() error {
	for _, tool := range []struct {
		cmd    string
		verify []string
		commit []string
	}{
		{"update-grub", []string{}, []string{}},
		{"grub2-mkconfig", []string{"-o", "/dev/null"}, []string{"-o", "/boot/grub2/grub.cfg"}},
		{"grub-mkconfig", []string{"-o", "/dev/null"}, []string{"-o", "/boot/grub/grub.cfg"}},
	} {
		if !commandExists(tool.cmd) {
			continue
		}
		if len(tool.verify) > 0 {
			if _, err := runCommand(tool.cmd, tool.verify...); err != nil {
				return err
			}
		}
		if _, err := runCommand(tool.cmd, tool.commit...); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("aucun outil de generation GRUB trouve")
}

// ---------------------------------------------------------------------------
// Synchronisation horaire (ntp_config)
// ---------------------------------------------------------------------------

const timesyncdDropIn = "/etc/systemd/timesyncd.conf.d/99-vaultaire-gpo.conf"

// applyNTPConfig fixe les serveurs de temps.
func applyNTPConfig(ctx Context, m Module) (string, error) {
	if m.Param("state") == "absent" {
		if err := os.Remove(timesyncdDropIn); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		_, _ = runCommand("systemctl", "restart", "systemd-timesyncd")
		return "serveurs NTP rendus a la configuration locale", nil
	}

	servers := normalizeList(m.Param("servers"))
	if servers == "" {
		return "", fmt.Errorf("aucun serveur NTP fourni")
	}

	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n[Time]\n")
	b.WriteString("NTP=" + servers + "\n")
	if fallback := normalizeList(m.Param("fallback_servers")); fallback != "" {
		b.WriteString("FallbackNTP=" + fallback + "\n")
	}

	if err := writeSystemFile(timesyncdDropIn, b.String(), 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "restart", "systemd-timesyncd"); err != nil {
		// Un timesyncd absent n'est pas une erreur : la machine utilise peut-être
		// chrony ou ntpd. Le fichier reste en place et servira si timesyncd est
		// installé plus tard.
		return "serveurs NTP ecrits (" + servers + "), systemd-timesyncd non redemarre", nil
	}
	return "serveurs NTP : " + servers, nil
}

// ---------------------------------------------------------------------------
// Rétention des journaux (log_policy)
// ---------------------------------------------------------------------------

const journaldDropIn = "/etc/systemd/journald.conf.d/99-vaultaire-gpo.conf"

// applyLogPolicy règle la taille et la durée de conservation des journaux.
func applyLogPolicy(ctx Context, m Module) (string, error) {
	if m.Param("state") == "absent" {
		if err := os.Remove(journaldDropIn); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		_, _ = runCommand("systemctl", "restart", "systemd-journald")
		return "retention des journaux rendue a la configuration locale", nil
	}

	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n[Journal]\n")
	var applied []string

	if maxUse := m.Param("max_use"); maxUse != "" {
		if !validSystemdSize(maxUse) {
			return "", fmt.Errorf("taille %q invalide : forme attendue 500M, 2G", maxUse)
		}
		b.WriteString("SystemMaxUse=" + maxUse + "\n")
		applied = append(applied, "taille<="+maxUse)
	}
	if days := intParam(m, "max_retention_days"); days > 0 {
		fmt.Fprintf(&b, "MaxRetentionSec=%dday\n", days)
		applied = append(applied, fmt.Sprintf("conservation %dj", days))
	}
	if fwd := m.Param("forward_to_syslog"); fwd != "" && fwd != "unchanged" {
		b.WriteString("ForwardToSyslog=" + fwd + "\n")
		applied = append(applied, "syslog="+fwd)
	}

	if len(applied) == 0 {
		return "aucun parametre fourni, rien a appliquer", nil
	}
	if err := writeSystemFile(journaldDropIn, b.String(), 0o644); err != nil {
		return "", err
	}
	_, _ = runCommand("systemctl", "restart", "systemd-journald")
	return strings.Join(applied, ", "), nil
}

// validSystemdSize vérifie la forme d'une taille systemd (nombre + suffixe).
func validSystemdSize(raw string) bool {
	if len(raw) < 2 {
		return false
	}
	suffix := raw[len(raw)-1]
	if !strings.ContainsRune("KMGT", rune(suffix)) {
		return false
	}
	_, err := strconv.Atoi(raw[:len(raw)-1])
	return err == nil
}

// ---------------------------------------------------------------------------
// Mises à jour automatiques (update_policy)
// ---------------------------------------------------------------------------

// applyUpdatePolicy active ou désactive les mises à jour automatiques.
func applyUpdatePolicy(ctx Context, m Module) (string, error) {
	manager, err := detectPackageManager()
	if err != nil {
		return "", err
	}
	enabled := m.Param("enabled")
	if enabled == "" || enabled == "unchanged" {
		return "aucun changement demande", nil
	}

	if manager == "apt-get" {
		return applyUnattendedUpgrades(m, enabled)
	}
	return applyDnfAutomatic(m, enabled)
}

// applyUnattendedUpgrades règle unattended-upgrades (Debian/Ubuntu).
func applyUnattendedUpgrades(m Module, enabled string) (string, error) {
	const path = "/etc/apt/apt.conf.d/99-vaultaire-gpo"

	if enabled == "disabled" {
		content := "// Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
			"APT::Periodic::Unattended-Upgrade \"0\";\n" +
			"APT::Periodic::Update-Package-Lists \"0\";\n"
		if err := writeSystemFile(path, content, 0o644); err != nil {
			return "", err
		}
		return "mises a jour automatiques desactivees", nil
	}

	var b strings.Builder
	b.WriteString("// Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	b.WriteString("APT::Periodic::Update-Package-Lists \"1\";\n")
	b.WriteString("APT::Periodic::Unattended-Upgrade \"1\";\n")

	reboot := "false"
	detail := "mises a jour automatiques activees"
	if m.Param("security_only") != "false" {
		detail += " (securite uniquement)"
	}
	if m.Param("reboot_if_needed") == "true" {
		reboot = "true"
		detail += ", redemarrage automatique"
		if t := m.Param("reboot_time"); t != "" {
			if !validHHMM(t) {
				return "", fmt.Errorf("heure %q invalide : forme attendue HH:MM", t)
			}
			b.WriteString("Unattended-Upgrade::Automatic-Reboot-Time \"" + t + "\";\n")
			detail += " a " + t
		}
	}
	b.WriteString("Unattended-Upgrade::Automatic-Reboot \"" + reboot + "\";\n")

	if err := writeSystemFile(path, b.String(), 0o644); err != nil {
		return "", err
	}
	return detail, nil
}

// applyDnfAutomatic règle dnf-automatic (RHEL/Rocky/Fedora).
func applyDnfAutomatic(m Module, enabled string) (string, error) {
	unit := "dnf-automatic.timer"
	if enabled == "disabled" {
		_, _ = runCommand("systemctl", "disable", "--now", unit)
		return "mises a jour automatiques desactivees", nil
	}

	const path = "/etc/dnf/automatic.conf.d/99-vaultaire-gpo.conf"
	upgradeType := "default"
	detail := "mises a jour automatiques activees"
	if m.Param("security_only") != "false" {
		upgradeType = "security"
		detail += " (securite uniquement)"
	}
	content := "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
		"[commands]\nupgrade_type = " + upgradeType + "\napply_updates = yes\n"
	if err := writeSystemFile(path, content, 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "enable", "--now", unit); err != nil {
		return "", fmt.Errorf("activation de %s impossible : %v", unit, err)
	}

	// dnf-automatic ne redémarre jamais la machine de lui-même : le champ est
	// sans effet ici, et le taire laisserait croire qu'il agit.
	if m.Param("reboot_if_needed") == "true" {
		detail += " (redemarrage automatique non gere par dnf-automatic, champ ignore)"
	}
	return detail, nil
}

// validHHMM vérifie une heure au format HH:MM.
func validHHMM(raw string) bool {
	_, err := time.Parse("15:04", raw)
	return err == nil
}

// ---------------------------------------------------------------------------
// Variable d'environnement système (system_env)
// ---------------------------------------------------------------------------

const environmentPath = "/etc/environment"

// applySystemEnv définit une variable dans /etc/environment.
//
// Le fichier est partagé et contient souvent des lignes posées à
// l'installation : on remplace la ligne de LA variable visée et on laisse le
// reste intact, plutôt que de réécrire le fichier entier.
func applySystemEnv(ctx Context, m Module) (string, error) {
	name := strings.ToUpper(m.Param("name"))
	if name == "" {
		return "", fmt.Errorf("nom de variable manquant")
	}

	content, _ := readFileIfExists(environmentPath)
	var kept []string
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, name+"=") {
			continue
		}
		kept = append(kept, line)
	}

	if m.Param("state") == "absent" {
		if err := writeSystemFile(environmentPath, strings.Join(kept, "\n")+"\n", 0o644); err != nil {
			return "", err
		}
		return "variable systeme " + name + " retiree", nil
	}

	value := m.Param("value")
	if strings.ContainsAny(value, "\n\r") {
		return "", fmt.Errorf("la valeur doit tenir sur une seule ligne")
	}
	kept = append(kept, name+"="+strconv.Quote(value))

	if err := writeSystemFile(environmentPath, strings.Join(kept, "\n")+"\n", 0o644); err != nil {
		return "", err
	}
	return "variable systeme " + name + " definie", nil
}

// ---------------------------------------------------------------------------
// Limites de ressources machine (resource_limits)
// ---------------------------------------------------------------------------

// applyResourceLimits fixe une limite dans /etc/security/limits.d/.
func applyResourceLimits(ctx Context, m Module) (string, error) {
	domain := m.Param("domain")
	limitType := m.Param("limit_type")
	item := m.Param("item")
	if domain == "" || limitType == "" || item == "" {
		return "", fmt.Errorf("portee, type ou ressource manquant")
	}

	// Le nom de fichier encode la clé naturelle : un fichier par triplet, donc
	// retirer une limite ne touche pas les autres.
	safeDomain := strings.NewReplacer("*", "all", "@", "grp-", "/", "-").Replace(domain)
	path := fmt.Sprintf("/etc/security/limits.d/99-vaultaire-%s-%s-%s.conf", safeDomain, limitType, item)

	if m.Param("state") == "absent" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		return "limite " + item + " retiree pour " + domain, nil
	}

	value := m.Param("value")
	if value != "unlimited" {
		if _, err := strconv.Atoi(value); err != nil {
			return "", fmt.Errorf("valeur %q invalide : entier ou « unlimited » attendu", value)
		}
	}

	content := fmt.Sprintf("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n%s %s %s %s\n",
		domain, limitType, item, value)
	if err := writeSystemFile(path, content, 0o644); err != nil {
		return "", err
	}
	// Les limites ne s'appliquent qu'aux NOUVELLES sessions : PAM les lit à
	// l'ouverture. Le dire évite de chercher pourquoi un shell déjà ouvert n'en
	// tient pas compte.
	return fmt.Sprintf("%s %s %s = %s (nouvelles sessions)", domain, limitType, item, value), nil
}

// ---------------------------------------------------------------------------
// Purge de fichiers (file_retention) — phase de ménage
// ---------------------------------------------------------------------------

// applyFileRetention supprime les fichiers dépassant un âge.
//
// Seul module du catalogue qui DÉTRUIT des données. Quatre garde-fous, chacun
// bloquant :
//
//   - le répertoire passe par les règles de chemin des Restrictions, comme
//     file_deploy — les emplacements refusés le sont aussi ici ;
//   - le motif ne peut pas contenir de séparateur, donc la purge ne peut pas
//     remonter ni descendre l'arborescence par le motif ;
//   - l'âge minimal est d'un jour, imposé par le schéma serveur ET revérifié
//     ici : une purge à zéro jour effacerait un fichier au moment de son
//     écriture ;
//   - les liens symboliques ne sont jamais suivis, sans quoi un lien posé dans
//     le répertoire ferait sortir la purge de son périmètre.
func applyFileRetention(ctx Context, m Module) (string, error) {
	dir := m.Param("directory")
	pattern := m.Param("pattern")
	days := intParam(m, "older_than_days")

	if dir == "" || pattern == "" {
		return "", fmt.Errorf("repertoire ou motif manquant")
	}
	if strings.ContainsAny(pattern, `/\`) {
		return "", fmt.Errorf("le motif %q contient un separateur de chemin : refuse", pattern)
	}
	if days < 1 {
		return "", fmt.Errorf("age minimal d'un jour requis, %d fourni", days)
	}

	cutoff := time.Now().AddDate(0, 0, -days)
	recursive := m.Param("recursive") == "true"

	var removed int
	var freed int64
	walk := func(current string) error {
		entries, err := os.ReadDir(current)
		if err != nil {
			return fmt.Errorf("lecture de %s impossible : %v", current, err)
		}
		for _, entry := range entries {
			full := filepath.Join(current, entry.Name())

			// Lstat et non Stat : on veut les métadonnées du lien lui-même.
			info, err := os.Lstat(full)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSymlink != 0 {
				continue
			}
			if info.IsDir() {
				continue
			}
			matched, err := filepath.Match(pattern, entry.Name())
			if err != nil {
				return fmt.Errorf("motif %q invalide : %v", pattern, err)
			}
			if !matched || info.ModTime().After(cutoff) {
				continue
			}
			size := info.Size()
			if err := os.Remove(full); err != nil {
				continue
			}
			removed++
			freed += size
		}
		return nil
	}

	if err := walk(dir); err != nil {
		return "", err
	}
	if recursive {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}
				// Un seul niveau de descente. Une récursion complète depuis une
				// politique rendrait la portée réelle impossible à prévoir
				// depuis l'interface, alors que c'est une opération destructrice.
				if err := walk(filepath.Join(dir, entry.Name())); err != nil {
					return "", err
				}
			}
		}
	}

	if removed == 0 {
		return fmt.Sprintf("aucun fichier %s de plus de %d jours dans %s", pattern, days, dir), nil
	}
	return fmt.Sprintf("%d fichier(s) supprime(s) dans %s (%s, >%dj, %d Kio liberes)",
		removed, dir, pattern, days, freed/1024), nil
}
