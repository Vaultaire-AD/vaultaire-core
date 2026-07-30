package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Appliqueurs des modules de scope utilisateur, plus le déploiement de fichier
// qui vaut dans les deux scopes.
//
// Tout ce qui est écrit ici appartient à l'utilisateur cible, jamais à root :
// les fichiers sont créés puis rattachés à son uid/gid. Un fichier appartenant à
// root dans le home d'un utilisateur l'empêcherait de le modifier et
// ressemblerait à une panne inexplicable de son côté.

const (
	// userEnvFileName est le fichier sourcé depuis le shell de l'utilisateur.
	userEnvFileName = ".vaultaire_env"
	// userProfileHook est le fichier où Vaultaire pose l'instruction de sourcing.
	userProfileHook = ".profile.d-vaultaire"
)

// applyUserEnv pose une variable d'environnement pour l'utilisateur.
//
// Vaultaire n'écrit pas dans .bashrc ni .profile : ces fichiers appartiennent à
// l'utilisateur, et le serveur en interdit d'ailleurs l'écriture. Il maintient
// un fichier qui lui appartient, et un bloc balisé dans le hook de sourcing.
func applyUserEnv(ctx Context, m Module) (string, error) {
	if ctx.Scope != ScopeUser || ctx.Username == "" {
		return "", fmt.Errorf("module reserve au scope utilisateur")
	}
	name := strings.ToUpper(m.Param("name"))
	value := m.Param("value")
	if name == "" {
		return "", fmt.Errorf("nom de variable manquant")
	}

	envPath := filepath.Join(ctx.HomeDir, userEnvFileName)
	existing, _ := readFileIfExists(envPath)

	// Une ligne par variable, remplacée à l'identique : les autres variables
	// posées par d'autres modules de la même politique doivent survivre.
	lines := []string{}
	replaced := false
	prefix := "export " + name + "="
	for _, line := range strings.Split(existing, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			lines = append(lines, prefix+shellQuote(value))
			replaced = true
			continue
		}
		lines = append(lines, trimmed)
	}
	if !replaced {
		lines = append(lines, prefix+shellQuote(value))
	}

	content := "# Fichier genere par Vaultaire GPO. Ne pas editer a la main.\n" +
		strings.Join(lines, "\n") + "\n"

	if err := writeUserFile(ctx, envPath, content, 0o644); err != nil {
		return "", err
	}
	if err := ensureProfileHook(ctx, envPath); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s defini pour %s", name, ctx.Username), nil
}

// ensureProfileHook garantit que le fichier d'environnement est sourcé.
func ensureProfileHook(ctx Context, envPath string) error {
	hookPath := filepath.Join(ctx.HomeDir, userProfileHook)
	existing, _ := readFileIfExists(hookPath)
	block := fmt.Sprintf("if [ -r %q ]; then . %q; fi", envPath, envPath)
	return writeUserFile(ctx, hookPath, replaceManagedBlock(existing, block), 0o644)
}

// applyUserCron installe ou retire un timer systemd utilisateur.
//
// systemd --user plutôt que crontab : les unités sont listables, auditables et
// révocables individuellement, là où une crontab est un fichier unique que
// plusieurs sources se disputeraient.
func applyUserCron(ctx Context, m Module) (string, error) {
	if ctx.Scope != ScopeUser || ctx.Username == "" {
		return "", fmt.Errorf("module reserve au scope utilisateur")
	}
	commandID := m.Param("command_id")
	schedule := m.Param("schedule")
	state := m.Param("state")
	if commandID == "" {
		return "", fmt.Errorf("identifiant de commande manquant")
	}

	command, err := cronCommandFor(commandID)
	if err != nil {
		return "", err
	}

	unitDir := filepath.Join(ctx.HomeDir, ".config", "systemd", "user")
	serviceName := "vaultaire-" + commandID + ".service"
	timerName := "vaultaire-" + commandID + ".timer"
	servicePath := filepath.Join(unitDir, serviceName)
	timerPath := filepath.Join(unitDir, timerName)

	if state == "absent" {
		_ = runUserSystemctl(ctx, "disable", "--now", timerName)
		removed := 0
		for _, path := range []string{servicePath, timerPath} {
			if err := os.Remove(path); err == nil {
				removed++
			}
		}
		return fmt.Sprintf("tache %s retiree (%d unite(s))", commandID, removed), nil
	}

	onCalendar, err := cronToOnCalendar(schedule)
	if err != nil {
		return "", err
	}

	serviceUnit := fmt.Sprintf(
		"# Genere par Vaultaire GPO. Ne pas editer a la main.\n"+
			"[Unit]\nDescription=Vaultaire GPO — %s\n\n"+
			"[Service]\nType=oneshot\nExecStart=%s\n", commandID, command)

	timerUnit := fmt.Sprintf(
		"# Genere par Vaultaire GPO. Ne pas editer a la main.\n"+
			"[Unit]\nDescription=Vaultaire GPO — planification de %s\n\n"+
			"[Timer]\nOnCalendar=%s\nPersistent=true\n\n"+
			"[Install]\nWantedBy=timers.target\n", commandID, onCalendar)

	if err := writeUserFile(ctx, servicePath, serviceUnit, 0o644); err != nil {
		return "", err
	}
	if err := writeUserFile(ctx, timerPath, timerUnit, 0o644); err != nil {
		return "", err
	}

	_ = runUserSystemctl(ctx, "daemon-reload")
	if err := runUserSystemctl(ctx, "enable", "--now", timerName); err != nil {
		// L'unité est en place : elle démarrera à la prochaine ouverture de
		// session même si le bus utilisateur n'est pas joignable maintenant
		// (cas courant hors session graphique).
		return "", fmt.Errorf("unites ecrites mais activation impossible : %v", err)
	}
	return fmt.Sprintf("tache %s planifiee (%s)", commandID, onCalendar), nil
}

// cronCommandFor traduit un identifiant de tâche en commande concrète.
//
// Même principe que les jeux de commandes sudo : la politique ne transporte
// qu'un identifiant, l'implémentation est ici. Un identifiant sans
// correspondance est une erreur explicite, pas une tâche vide.
func cronCommandFor(commandID string) (string, error) {
	commands := map[string]string{
		"backup_home":       "/usr/bin/tar -czf %h/.vaultaire-backup.tar.gz --exclude=.vaultaire-backup.tar.gz %h",
		"cleanup_tmp":       "/usr/bin/find %h/tmp -type f -mtime +7 -delete",
		"report_disk_usage": "/usr/bin/du -sh %h",
		"sync_dotfiles":     "/usr/bin/true",
		"rotate_user_logs":  "/usr/bin/find %h/.local/log -type f -mtime +30 -delete",
	}
	command, ok := commands[commandID]
	if !ok {
		return "", fmt.Errorf(
			"tache %q inconnue de cet agent : elle existe cote serveur mais pas son implementation locale", commandID)
	}
	return command, nil
}

// cronToOnCalendar convertit une expression cron à 5 champs en OnCalendar.
//
// Conversion volontairement limitée aux formes que le serveur accepte déjà
// (valeurs fixes, * et pas /n). Une expression plus riche est refusée plutôt
// que traduite approximativement : un timer qui se déclenche au mauvais moment
// est plus difficile à diagnostiquer qu'un module en échec.
func cronToOnCalendar(schedule string) (string, error) {
	fields := strings.Fields(schedule)
	if len(fields) != 5 {
		return "", fmt.Errorf("expression cron a 5 champs attendue, recu %q", schedule)
	}
	minute, hour, dom, month, dow := fields[0], fields[1], fields[2], fields[3], fields[4]

	for _, f := range fields {
		if strings.ContainsAny(f, ",-/") {
			return "", fmt.Errorf(
				"expression cron %q trop complexe pour la conversion en OnCalendar (listes, plages et pas non geres)", schedule)
		}
	}

	weekday := ""
	if dow != "*" {
		names := map[string]string{
			"0": "Sun", "1": "Mon", "2": "Tue", "3": "Wed",
			"4": "Thu", "5": "Fri", "6": "Sat", "7": "Sun",
		}
		name, ok := names[dow]
		if !ok {
			return "", fmt.Errorf("jour de semaine %q invalide", dow)
		}
		weekday = name + " "
	}

	pad := func(value, wildcard string) string {
		if value == "*" {
			return wildcard
		}
		if len(value) == 1 {
			return "0" + value
		}
		return value
	}

	return fmt.Sprintf("%s*-%s-%s %s:%s:00",
		weekday, pad(month, "*"), pad(dom, "*"), pad(hour, "*"), pad(minute, "*")), nil
}

// runUserSystemctl exécute systemctl --user pour le compte de l'utilisateur.
func runUserSystemctl(ctx Context, args ...string) error {
	if !commandExists("systemctl") {
		return fmt.Errorf("systemctl absent de cette machine")
	}
	if !commandExists("runuser") {
		return fmt.Errorf("runuser absent de cette machine")
	}
	// Délai court : cette commande est sur le chemin d'ouverture de session et
	// attend le bus utilisateur, qui peut ne jamais démarrer hors session.
	full := append([]string{"-u", ctx.Username, "--", "systemctl", "--user"}, args...)
	_, err := runCommandTimeout(UserCommandTimeout, "runuser", full...)
	return err
}

// applyFileDeploy dépose ou retire un fichier. Valable dans les deux scopes.
func applyFileDeploy(ctx Context, m Module) (string, error) {
	rawPath := m.Param("path")
	state := m.Param("state")
	if rawPath == "" {
		return "", fmt.Errorf("chemin manquant")
	}

	path, err := expandHome(ctx, rawPath)
	if err != nil {
		return "", err
	}

	if state == "absent" {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return path + " deja absent", nil
			}
			return "", fmt.Errorf("suppression de %s impossible : %v", path, err)
		}
		return path + " supprime", nil
	}

	mode, err := parseFileMode(m.Param("mode"))
	if err != nil {
		return "", err
	}
	content := m.RawParam("content")

	if ctx.Scope == ScopeUser {
		if err := writeUserFile(ctx, path, content, os.FileMode(mode)); err != nil {
			return "", err
		}
		return fmt.Sprintf("%s ecrit (%d octets, %04o, %s)", path, len(content), mode, ctx.Username), nil
	}

	if err := writeSystemFile(path, content, os.FileMode(mode)); err != nil {
		return "", err
	}
	if owner := m.Param("owner"); owner != "" {
		group := m.Param("group")
		if group == "" {
			group = owner
		}
		if commandExists("chown") {
			if _, err := runCommand("chown", owner+":"+group, path); err != nil {
				return "", fmt.Errorf("fichier ecrit mais proprietaire non applique : %v", err)
			}
		}
	}
	return fmt.Sprintf("%s ecrit (%d octets, %04o)", path, len(content), mode), nil
}

// ---------------------------------------------------------------------------
// Utilitaires scope utilisateur
// ---------------------------------------------------------------------------

// writeUserFile écrit un fichier appartenant à l'utilisateur cible.
func writeUserFile(ctx Context, path, content string, mode os.FileMode) error {
	if ctx.Username == "" {
		return fmt.Errorf("utilisateur cible non defini")
	}
	uid, gid, err := resolveUserIDs(ctx.Username)
	if err != nil {
		return err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creation de %s impossible : %v", dir, err)
	}
	// Les répertoires intermédiaires créés sous le home doivent eux aussi
	// appartenir à l'utilisateur, sinon il ne peut rien y écrire ensuite.
	if err := chownTree(ctx.HomeDir, dir, uid, gid); err != nil {
		return err
	}

	if err := writeSystemFile(path, content, mode); err != nil {
		return err
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("proprietaire de %s non applique : %v", path, err)
	}
	return nil
}

// chownTree rattache à l'utilisateur les répertoires créés sous son home.
func chownTree(homeDir, dir string, uid, gid int) error {
	if homeDir == "" || !strings.HasPrefix(dir, homeDir) {
		return nil
	}
	current := dir
	for len(current) > len(homeDir) {
		if err := os.Chown(current, uid, gid); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("proprietaire de %s non applique : %v", current, err)
		}
		current = filepath.Dir(current)
	}
	return nil
}

// shellQuote protège une valeur destinée à un fichier sourcé par le shell.
//
// La valeur vient d'une politique validée côté serveur, mais elle est écrite
// dans un fichier que le shell interprète : sans protection, une apostrophe
// suffirait à faire exécuter autre chose à l'ouverture de session.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
