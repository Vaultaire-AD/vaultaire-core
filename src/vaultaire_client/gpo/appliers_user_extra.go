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

	// SOUS UN `HOME`, `setfacl` NE REÇOIT PLUS UN CHEMIN — TO-DO 162.
	//
	// `setfacl` suit les liens de l'argument qu'on lui donne, et il tourne ici
	// EN ROOT sur un dossier que l'utilisateur contrôle. Avec
	// `ln -s /etc/shadow ~/partage`, une politique « donner au groupe X l'accès
	// à /%h/partage » donnait à X l'accès à `/etc/shadow`. Le contrôle du
	// serveur porte sur le chemin déclaré, qui est légitime ; la traversée a
	// lieu ici, sur un système de fichiers que la personne vient de modifier.
	//
	// Vérifier le chemin puis appeler la commande ne ferme rien : il est
	// remplacé entre les deux. La cible est donc OUVERTE par la descente du
	// point 97, et c'est son descripteur que la commande reçoit, sous la forme
	// `/proc/<pid>/fd/<n>` — que le noyau résout vers l'objet lui-même.
	//
	// Le scope machine garde le chemin, pour la raison écrite dans
	// writeSystemFile : planter un lien sous `/etc` demande déjà d'être root.
	cible := path
	if ctx.Scope == ScopeUser {
		uid, _, err := idsDuCompte(ctx)
		if err != nil {
			return "", err
		}
		objet, err := designerSousHome(ctx.HomeDir, path, uid)
		if err != nil {
			return "", err
		}
		defer objet.Close()
		cible = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), objet.Fd())
		if info, err := objet.Stat(); err == nil && info.IsDir() {
			// « /. » : le lien magique de /proc est alors traversé comme un
			// composant intermédiaire, et l'argument lui-même est un vrai
			// répertoire. Sans cela, « -P » — indispensable en récursif, voir
			// plus bas — écarterait l'argument entier, puisqu'il écarte les
			// arguments qui sont des liens.
			cible += "/."
		}
	}

	kind := m.Param("kind")
	target := m.Param("target")
	if target == "" {
		return "", fmt.Errorf("beneficiaire manquant")
	}
	genre := map[string]string{"user": "u", "group": "g"}[kind]
	spec := genre + ":" + target

	recursif := m.Param("recursive") == "true"

	// verifiable : ce que le vérificateur saura CONSTATER, et rien de plus.
	//
	// Faux dès que la politique est récursive. getfacl ne constaterait alors que
	// le chemin de tête, et une ACL retirée sur un sous-répertoire passerait pour
	// conforme — c'est-à-dire une affirmation plus large que le constat.
	//
	// Le silence est un défaut de COUVERTURE, connu et écrit dans la
	// documentation. La fausse conformité est un défaut de CONFIANCE, et il ne
	// se limite pas au module fautif : il décrédibilise tout le rapport.
	//
	// Faux aussi sur un genre inconnu : « spec » vaudrait « :alice », que
	// getfacl n'écrit jamais, et le vérificateur conclurait « entrée disparue »
	// sur une machine où elle n'a jamais existé.
	verifiable := !recursif && genre != ""

	var args []string
	if recursif {
		args = append(args, "-R")
		if ctx.Scope == ScopeUser {
			// Parcours PHYSIQUE : sous un `HOME`, un lien rencontré pendant la
			// descente ne doit pas emmener `setfacl` hors du dossier. Sans ce
			// drapeau, la récursion suivait `~/partage/lien -> /etc`.
			args = append(args, "-P")
		}
	}

	if m.Param("state") == "absent" {
		args = append(args, "-x", spec, cible)
		if _, err := runCommand("setfacl", args...); err != nil {
			return "", err
		}
		if verifiable {
			ctx.recordCheck(CheckFileACL, path+"|"+spec, "absent")
		}
		return "ACL " + spec + " retiree de " + path, nil
	}

	perms := m.Param("permissions")
	if perms == "---" {
		// setfacl n'accepte pas « --- » : l'absence de droit s'exprime par une
		// chaîne vide après les deux-points.
		perms = ""
	}
	args = append(args, "-m", spec+":"+perms, cible)
	if _, err := runCommand("setfacl", args...); err != nil {
		return "", err
	}
	if verifiable {
		// Les droits ORIGINAUX, pas « perms » : « --- » a été remplacé par la
		// chaîne vide pour setfacl, alors que getfacl rend bien « --- ». Déclarer
		// l'attente sur la forme envoyée à setfacl produirait un écart permanent.
		ctx.recordCheck(CheckFileACL, path+"|"+spec, m.Param("permissions"))
	}

	detail := "ACL " + spec + ":" + m.Param("permissions") + " sur " + path
	if recursif {
		// L'ACL par défaut fait hériter les fichiers créés ENSUITE. Sans elle,
		// la récursion ne vaudrait que pour le contenu présent au moment de
		// l'application, et la politique se dégraderait silencieusement.
		defaultArgs := []string{"-R"}
		if ctx.Scope == ScopeUser {
			defaultArgs = append(defaultArgs, "-P")
		}
		defaultArgs = append(defaultArgs, "-d", "-m", spec+":"+perms, cible)
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

	// L'appartenance est l'effet le plus lourd de ce paquet : « sudo » et
	// « wheel » passent par ici. Remettre quelqu'un dans sudo à la main ne
	// laissait aucune trace et ne produisait aucun écart.
	if m.Param("state") == "absent" {
		ctx.recordCheck(CheckGroupMember, ctx.Username+":"+group, "absent")
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
	ctx.recordCheck(CheckGroupMember, ctx.Username+":"+group, "member")
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
	// Le shell ne laisse aucune trace dans un fichier déposé par la GPO :
	// usermod réécrit /etc/passwd, que le scan des fichiers ne surveille pas —
	// et ne doit pas surveiller, puisque toute création de compte le modifie.
	// Sans cette attente, un « chsh » local passait inaperçu.
	ctx.recordCheck(CheckUserShell, ctx.Username, shell)
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

	begin, end, ok := marqueursSSH(alias)
	if !ok {
		return "", fmt.Errorf("alias manquant")
	}
	bloc := prefixeBlocSSH + alias

	// Relu SANS suivre de lien (TO-DO 135) : `os.ReadFile` lisait à travers un
	// `~/.ssh/config` devenu lien, et la réécriture qui suit recopiait la cible
	// dans un fichier appartenant à l'utilisateur. Un lien, ou un fichier d'un
	// autre compte, est ici une ERREUR : le module échoue et le journal le dit,
	// plutôt que de remplacer en silence ce que la personne a mis là.
	existing, _, err := readUserFile(ctx, path)
	if err != nil {
		return "", err
	}
	// Le bloc balisé est retiré puis réécrit : le reste du fichier, qui
	// appartient à l'utilisateur, n'est jamais touché.
	rebuilt := removeMarkedBlock(existing, begin, end)

	if m.Param("state") == "absent" {
		if strings.TrimSpace(rebuilt) == "" {
			if err := removeUserBlock(ctx, path, bloc); err != nil {
				return "", err
			}
			return "alias " + alias + " retire", nil
		}
		if err := writeUserBlock(ctx, path, rebuilt+"\n", 0o600, bloc); err != nil {
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
	//
	// Inscrit comme un BLOC : le reste de ce fichier est à la personne, et lui
	// ajouter un hôte n'est pas une dérive.
	if err := writeUserBlock(ctx, path, content, 0o600, bloc); err != nil {
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
	uid, gid, err := idsDuCompte(ctx)
	if err != nil {
		return "", err
	}

	// `git` NE TRAVAILLE PLUS DANS LE `HOME` — TO-DO 162.
	//
	// # Ce que faisait la version précédente
	//
	//	git config --file ~/.gitconfig <cle> <valeur>     en root
	//	chown <compte>:<compte> ~/.gitconfig              en root
	//
	// `git` suit les liens pour écrire — il pose son verrou à côté de la CIBLE —
	// et `chown` les suit aussi. Avec `ln -s /etc/ld.so.preload ~/.gitconfig`,
	// root créait `/etc/ld.so.preload` puis le DONNAIT à l'utilisateur, qui n'avait
	// plus qu'à y inscrire sa bibliothèque pour être root. Même faille que le
	// point 97, par un appliqueur qu'il n'avait pas relu.
	//
	// # Ce qu'elle fait
	//
	// Le fichier est relu par la descente sûre, `git` travaille sur une COPIE
	// dans un répertoire que seul root peut ouvrir, et le résultat revient par
	// `ecrireFichierUtilisateur` — qui pose propriétaire et mode sur le
	// descripteur. Plus aucune commande ne reçoit un chemin que l'utilisateur
	// contrôle, et `chownToUser` a disparu avec sa raison d'être.
	existant, existait, err := lireFichierUtilisateur(ctx.HomeDir, path, uid)
	if err != nil {
		return "", err
	}

	retirer := m.Param("state") == "absent"
	if retirer && !existait {
		return "cle git " + key + " deja absente", nil
	}

	atelier, err := os.MkdirTemp("", "vaultaire-git-")
	if err != nil {
		return "", fmt.Errorf("repertoire de travail impossible : %v", err)
	}
	defer os.RemoveAll(atelier)
	copie := atelier + "/config"
	if err := os.WriteFile(copie, []byte(existant), 0o600); err != nil {
		return "", fmt.Errorf("copie de travail impossible : %v", err)
	}

	value := m.Param("value")
	if retirer {
		// --unset échoue si la clé n'existe pas : l'état voulu est déjà atteint.
		_, _ = runCommandTimeout(UserCommandTimeout, "git", "config", "--file", copie, "--unset", key)
	} else if _, err := runCommandTimeout(UserCommandTimeout, "git", "config", "--file", copie, key, value); err != nil {
		return "", fmt.Errorf("ecriture de %s impossible : %v", key, err)
	}

	nouveau, err := os.ReadFile(copie)
	if err != nil {
		return "", fmt.Errorf("relecture de la copie de travail impossible : %v", err)
	}
	if string(nouveau) != existant || !existait {
		// Ce fichier appartient à la personne et Vaultaire n'y tient qu'une
		// clé : rien n'est inscrit à l'inventaire, exactement comme avant — en
		// hacher la totalité ferait une dérive de chaque `git config` qu'elle
		// lance. La clé elle-même n'a pas encore de vérificateur (TO-DO 163).
		if err := ecrireFichierUtilisateur(ctx.HomeDir, path, string(nouveau), 0o644, uid, gid); err != nil {
			return "", err
		}
	}
	if retirer {
		return "cle git " + key + " retiree", nil
	}
	return "git " + key + " = " + value, nil
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
		if _, err := ctx.removeSystemFile(path); err != nil {
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
	if err := ctx.writeSystemFile(path, b.String(), 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "daemon-reload"); err != nil {
		return "", fmt.Errorf("quotas ecrits mais systemd non recharge : %v", err)
	}
	return strings.Join(applied, ", ") + " (effectif a la prochaine session)", nil
}
