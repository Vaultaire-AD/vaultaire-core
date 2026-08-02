package gpo

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Appliqueurs d'ACL et d'environnement utilisateur.

// ---------------------------------------------------------------------------
// ACL POSIX (file_acl)
// ---------------------------------------------------------------------------

// applyFileACL pose ou retire une ACL POSIX.
func applyFileACL(ctx Context, m Module) (string, error) {
	if !commandExists("setfacl") {
		return "", fmt.Errorf("setfacl absent : installez le paquet acl (module package)")
	}

	path, err := expandHome(ctx, m.Param("path"))
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(path); err != nil {
		// Une ACL sur un chemin inexistant est une erreur de politique, pas un
		// cas à ignorer : le module qui devait déposer la cible manque, ou son
		// ordre est postérieur.
		return "", fmt.Errorf("cible %s absente : le module qui la depose manque dans la politique, ou passe apres", path)
	}

	kind := m.Param("kind")
	target := m.Param("target")
	if target == "" {
		return "", fmt.Errorf("beneficiaire manquant")
	}
	spec := map[string]string{"user": "u", "group": "g"}[kind] + ":" + target

	var args []string
	if m.Param("recursive") == "true" {
		args = append(args, "-R")
	}

	if m.Param("state") == "absent" {
		args = append(args, "-x", spec, path)
		if _, err := runCommand("setfacl", args...); err != nil {
			return "", err
		}
		return "ACL " + spec + " retiree de " + path, nil
	}

	perms := m.Param("permissions")
	if perms == "---" {
		// setfacl n'accepte pas « --- » : l'absence de droit s'exprime par une
		// chaîne vide après les deux-points.
		perms = ""
	}
	args = append(args, "-m", spec+":"+perms, path)
	if _, err := runCommand("setfacl", args...); err != nil {
		return "", err
	}

	detail := "ACL " + spec + ":" + m.Param("permissions") + " sur " + path
	if m.Param("recursive") == "true" {
		// L'ACL par défaut fait hériter les fichiers créés ENSUITE. Sans elle,
		// la récursion ne vaudrait que pour le contenu présent au moment de
		// l'application, et la politique se dégraderait silencieusement.
		defaultArgs := []string{"-R", "-d", "-m", spec + ":" + perms, path}
		if _, err := runCommand("setfacl", defaultArgs...); err != nil {
			return "", fmt.Errorf("ACL posee mais heritage non applique : %v", err)
		}
		detail += " (recursif, avec heritage)"
	}
	return detail, nil
}

// ---------------------------------------------------------------------------
// Appartenance à un groupe local (user_group_membership)
// ---------------------------------------------------------------------------

// applyUserGroupMembership ajoute ou retire l'utilisateur d'un groupe POSIX.
func applyUserGroupMembership(ctx Context, m Module) (string, error) {
	if ctx.Username == "" {
		return "", fmt.Errorf("utilisateur cible inconnu")
	}
	group := m.Param("group")
	if group == "" {
		return "", fmt.Errorf("groupe manquant")
	}

	// Le groupe doit exister localement. usermod -aG le créerait sinon
	// silencieusement sur certaines distributions, ce qui donnerait une
	// appartenance à un groupe vide de sens.
	if _, err := user.LookupGroup(group); err != nil {
		return "", fmt.Errorf("groupe local %s inexistant sur cette machine", group)
	}

	if m.Param("state") == "absent" {
		if _, err := runCommand("gpasswd", "-d", ctx.Username, group); err != nil {
			// gpasswd -d échoue si l'utilisateur n'est pas membre : ce n'est pas
			// une erreur, l'état voulu est déjà atteint.
			return ctx.Username + " n'etait pas membre de " + group, nil
		}
		return ctx.Username + " retire du groupe " + group, nil
	}

	if _, err := runCommandTimeout(UserCommandTimeout, "usermod", "-aG", group, ctx.Username); err != nil {
		return "", fmt.Errorf("ajout au groupe %s impossible : %v", group, err)
	}
	// L'appartenance ne vaut que pour les sessions OUVERTES ENSUITE : les
	// identifiants de groupe sont figés à l'ouverture de session. Le dire évite
	// de chercher pourquoi la commande refuse encore l'accès.
	return ctx.Username + " ajoute au groupe " + group + " (effectif a la prochaine session)", nil
}

// ---------------------------------------------------------------------------
// Shell de connexion (user_shell)
// ---------------------------------------------------------------------------

// applyUserShell force le shell de connexion.
func applyUserShell(ctx Context, m Module) (string, error) {
	if ctx.Username == "" {
		return "", fmt.Errorf("utilisateur cible inconnu")
	}
	shell := m.Param("shell")
	if shell == "" {
		return "", fmt.Errorf("shell manquant")
	}

	// Le shell doit exister ET être exécutable. Un chemin absent rend le compte
	// inutilisable : la connexion aboutit puis se referme aussitôt, sans message
	// exploitable pour l'utilisateur.
	info, err := os.Stat(shell)
	if err != nil {
		return "", fmt.Errorf("shell %s absent de cette machine", shell)
	}
	if info.Mode()&0o111 == 0 {
		return "", fmt.Errorf("shell %s non executable", shell)
	}

	if _, err := runCommandTimeout(UserCommandTimeout, "usermod", "-s", shell, ctx.Username); err != nil {
		return "", fmt.Errorf("changement de shell impossible : %v", err)
	}
	return "shell de " + ctx.Username + " : " + shell, nil
}

// ---------------------------------------------------------------------------
// Expiration du mot de passe utilisateur (user_password_policy)
// ---------------------------------------------------------------------------

// applyUserPasswordPolicy règle l'expiration du mot de passe.
func applyUserPasswordPolicy(ctx Context, m Module) (string, error) {
	if ctx.Username == "" {
		return "", fmt.Errorf("utilisateur cible inconnu")
	}

	var applied []string

	if maxAge := intParam(m, "max_age_days"); maxAge > 0 {
		if _, err := runCommandTimeout(UserCommandTimeout, "chage", "-M", strconv.Itoa(maxAge), ctx.Username); err != nil {
			return "", fmt.Errorf("age maximal impossible : %v", err)
		}
		applied = append(applied, fmt.Sprintf("validite %dj", maxAge))
	}
	if warn := intParam(m, "warn_days"); warn > 0 {
		if _, err := runCommandTimeout(UserCommandTimeout, "chage", "-W", strconv.Itoa(warn), ctx.Username); err != nil {
			return "", fmt.Errorf("delai d'avertissement impossible : %v", err)
		}
		applied = append(applied, fmt.Sprintf("avertissement %dj", warn))
	}

	if m.Param("force_change") == "true" {
		// Vérification du shell avant de forcer le changement. Avec un shell
		// nologin, l'utilisateur ne peut pas ouvrir de session, donc pas changer
		// son mot de passe, donc plus jamais se connecter : la politique
		// fabriquerait un compte définitivement bloqué.
		if shell, err := loginShellOf(ctx.Username); err == nil &&
			(strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false")) {
			return "", fmt.Errorf(
				"changement force refuse : le shell de %s est %s, l'utilisateur ne pourrait pas ouvrir de session pour changer son mot de passe",
				ctx.Username, shell)
		}
		if _, err := runCommandTimeout(UserCommandTimeout, "chage", "-d", "0", ctx.Username); err != nil {
			return "", fmt.Errorf("changement force impossible : %v", err)
		}
		applied = append(applied, "changement au prochain login")
	}

	if len(applied) == 0 {
		return "aucun parametre fourni, rien a appliquer", nil
	}
	return strings.Join(applied, ", "), nil
}

// loginShellOf retourne le shell de connexion d'un utilisateur.
func loginShellOf(username string) (string, error) {
	out, err := runCommandTimeout(UserCommandTimeout, "getent", "passwd", username)
	if err != nil {
		return "", err
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return "", fmt.Errorf("entree passwd illisible")
	}
	return fields[6], nil
}

// ---------------------------------------------------------------------------
// Configuration cliente SSH (user_ssh_client_config)
// ---------------------------------------------------------------------------

// applyUserSSHClientConfig écrit une entrée Host dans ~/.ssh/config.
func applyUserSSHClientConfig(ctx Context, m Module) (string, error) {
	alias := m.Param("host_alias")
	if alias == "" {
		return "", fmt.Errorf("alias manquant")
	}
	path := ctx.HomeDir + "/.ssh/config"

	begin := "# >>> vaultaire-gpo:" + alias + " >>>"
	end := "# <<< vaultaire-gpo:" + alias + " <<<"

	existing, _ := readFileIfExists(path)
	// Le bloc balisé est retiré puis réécrit : le reste du fichier, qui
	// appartient à l'utilisateur, n'est jamais touché.
	rebuilt := removeMarkedBlock(existing, begin, end)

	if m.Param("state") == "absent" {
		if strings.TrimSpace(rebuilt) == "" {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return "", err
			}
			return "alias " + alias + " retire", nil
		}
		if err := writeUserFile(ctx, path, rebuilt, 0o600); err != nil {
			return "", err
		}
		return "alias " + alias + " retire", nil
	}

	hostname := m.Param("hostname")
	if hostname == "" {
		return "", fmt.Errorf("hote reel manquant")
	}

	var b strings.Builder
	b.WriteString(begin + "\n")
	b.WriteString("Host " + alias + "\n")
	b.WriteString("    HostName " + hostname + "\n")
	if v := m.Param("user"); v != "" {
		b.WriteString("    User " + v + "\n")
	}
	if v := m.Param("port"); v != "" {
		b.WriteString("    Port " + v + "\n")
	}
	if v := m.Param("proxy_jump"); v != "" {
		b.WriteString("    ProxyJump " + v + "\n")
	}
	if v := m.Param("identity_file"); v != "" {
		b.WriteString("    IdentityFile " + ctx.HomeDir + "/" + strings.TrimPrefix(v, "/") + "\n")
	}
	b.WriteString(end + "\n")

	content := b.String()
	if strings.TrimSpace(rebuilt) != "" {
		content = strings.TrimRight(rebuilt, "\n") + "\n\n" + content
	}
	// 0600 : ssh refuse un fichier de configuration accessible aux autres.
	if err := writeUserFile(ctx, path, content, 0o600); err != nil {
		return "", err
	}
	return "alias SSH " + alias + " -> " + hostname, nil
}

// removeMarkedBlock retire un bloc délimité par deux balises.
func removeMarkedBlock(content, begin, end string) string {
	var out []string
	inside := false
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == begin {
			inside = true
			continue
		}
		if trimmed == end {
			inside = false
			continue
		}
		if !inside {
			out = append(out, line)
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// ---------------------------------------------------------------------------
// Configuration git (user_git_config)
// ---------------------------------------------------------------------------

// applyUserGitConfig règle une clé du .gitconfig de l'utilisateur.
//
// Passe par « git config » plutôt que par une écriture directe : l'outil connaît
// le format INI de git, y compris les sections déjà présentes, et une écriture
// manuelle finirait par dupliquer une section ou casser un fichier que
// l'utilisateur édite aussi.
func applyUserGitConfig(ctx Context, m Module) (string, error) {
	if !commandExists("git") {
		return "", fmt.Errorf("git absent : installez-le d'abord (module package)")
	}
	key := m.Param("key")
	if key == "" {
		return "", fmt.Errorf("cle manquante")
	}

	path := ctx.HomeDir + "/.gitconfig"

	if m.Param("state") == "absent" {
		// --unset échoue si la clé n'existe pas : l'état voulu est déjà atteint.
		_, _ = runCommandTimeout(UserCommandTimeout, "git", "config", "--file", path, "--unset", key)
		_ = chownToUser(ctx, path)
		return "cle git " + key + " retiree", nil
	}

	value := m.Param("value")
	if _, err := runCommandTimeout(UserCommandTimeout, "git", "config", "--file", path, key, value); err != nil {
		return "", fmt.Errorf("ecriture de %s impossible : %v", key, err)
	}
	// git crée le fichier en tant que root : sans reprise de propriété,
	// l'utilisateur ne pourrait plus modifier son propre .gitconfig.
	if err := chownToUser(ctx, path); err != nil {
		return "", err
	}
	return "git " + key + " = " + value, nil
}

// chownToUser rend un fichier à l'utilisateur cible.
func chownToUser(ctx Context, path string) error {
	if ctx.Username == "" || !commandExists("chown") {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	if _, err := runCommandTimeout(UserCommandTimeout, "chown", ctx.Username+":"+ctx.Username, path); err != nil {
		return fmt.Errorf("fichier ecrit mais proprietaire non applique : %v", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Quota de ressources utilisateur (user_resource_limits)
// ---------------------------------------------------------------------------

// applyUserResourceLimits limite CPU et mémoire via la slice systemd.
func applyUserResourceLimits(ctx Context, m Module) (string, error) {
	if ctx.Username == "" {
		return "", fmt.Errorf("utilisateur cible inconnu")
	}

	target, err := user.Lookup(ctx.Username)
	if err != nil {
		return "", fmt.Errorf("utilisateur %s inconnu localement", ctx.Username)
	}
	// La slice systemd d'un utilisateur est nommée par son UID, pas par son nom.
	path := fmt.Sprintf("/etc/systemd/system/user-%s.slice.d/99-vaultaire-gpo.conf", target.Uid)

	if m.Param("state") == "absent" {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		_, _ = runCommand("systemctl", "daemon-reload")
		return "quotas de " + ctx.Username + " retires", nil
	}

	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n[Slice]\n")
	var applied []string

	if quota := m.Param("cpu_quota"); quota != "" {
		if !strings.HasSuffix(quota, "%") {
			return "", fmt.Errorf("quota CPU %q invalide : pourcentage attendu, ex. 200%%", quota)
		}
		b.WriteString("CPUQuota=" + quota + "\n")
		applied = append(applied, "CPU "+quota)
	}
	if mem := m.Param("memory_max"); mem != "" {
		if !validSystemdSize(mem) {
			return "", fmt.Errorf("memoire %q invalide : forme attendue 512M, 4G", mem)
		}
		b.WriteString("MemoryMax=" + mem + "\n")
		applied = append(applied, "memoire "+mem)
	}
	if tasks := intParam(m, "tasks_max"); tasks > 0 {
		fmt.Fprintf(&b, "TasksMax=%d\n", tasks)
		applied = append(applied, fmt.Sprintf("%d processus", tasks))
	}

	if len(applied) == 0 {
		return "aucun quota fourni, rien a appliquer", nil
	}
	if err := writeSystemFile(path, b.String(), 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		return "", fmt.Errorf("quotas ecrits mais systemd non recharge : %v", err)
	}
	return strings.Join(applied, ", ") + " (effectif a la prochaine session)", nil
}
