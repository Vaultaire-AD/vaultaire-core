package gpo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Appliqueurs de durcissement — phase de configuration système.
//
// PRINCIPE COMMUN À TOUT CE FICHIER : chaque module écrit dans un fichier `.d/`
// qui lui est propre et vérifie son travail avant de le rendre effectif. En cas
// d'échec de la vérification, l'état précédent est restauré.
//
// Ce n'est pas de la prudence de principe. Ces modules touchent l'authentification,
// le démarrage et le contrôle d'accès obligatoire : une politique fautive appliquée
// à tout un parc rendrait les machines inaccessibles À DISTANCE, donc sans moyen
// d'y pousser la politique corrective. Le retour arrière local est le seul filet.

// ---------------------------------------------------------------------------
// Politique de mot de passe et de verrouillage (pam_policy)
// ---------------------------------------------------------------------------

const (
	pwqualityDropIn = "/etc/security/pwquality.conf.d/99-vaultaire-gpo.conf"
	faillockDropIn  = "/etc/security/faillock.conf"
)

// applyPAMPolicy règle la complexité des mots de passe et le verrouillage.
//
// N'ÉCRIT JAMAIS DANS /etc/pam.d/. Les piles PAM sont un ordre d'instructions :
// une ligne mal placée ne dégrade pas l'authentification, elle la casse — et le
// projet en a déjà fait l'expérience sur /etc/pam.d/login, où un `auth required`
// sans relais laissait un compte local incapable de se connecter en console.
//
// pwquality.conf.d et faillock.conf sont des fichiers de PARAMÈTRES lus par des
// modules déjà présents dans les piles des distributions. Y écrire une valeur
// aberrante durcit ou assouplit la politique ; ça ne peut pas empêcher PAM de
// fonctionner.
func applyPAMPolicy(ctx Context, m Module) (string, error) {
	if m.Param("state") == "absent" {
		var removed []string
		for _, path := range []string{pwqualityDropIn} {
			if _, err := removeSystemFile(path); err != nil {
				return "", fmt.Errorf("retrait de %s impossible : %v", path, err)
			}
			removed = append(removed, path)
		}
		if len(removed) == 0 {
			return "aucune politique Vaultaire a retirer", nil
		}
		return "politique retiree : " + strings.Join(removed, ", "), nil
	}

	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	var applied []string

	if v := intParam(m, "min_length"); v > 0 {
		fmt.Fprintf(&b, "minlen = %d\n", v)
		applied = append(applied, fmt.Sprintf("longueur>=%d", v))
	}
	if v := intParam(m, "min_classes"); v > 0 {
		fmt.Fprintf(&b, "minclass = %d\n", v)
		applied = append(applied, fmt.Sprintf("classes>=%d", v))
	}
	if v := intParam(m, "remember"); v > 0 {
		fmt.Fprintf(&b, "remember = %d\n", v)
		applied = append(applied, fmt.Sprintf("historique=%d", v))
	}

	if len(applied) > 0 {
		if err := writeSystemFile(pwqualityDropIn, b.String(), 0o644); err != nil {
			return "", err
		}
	}

	// faillock : verrouillage après échecs répétés.
	if deny := intParam(m, "deny_after"); deny > 0 {
		unlock := intParam(m, "unlock_time")
		var fb strings.Builder
		fb.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
		fmt.Fprintf(&fb, "deny = %d\n", deny)
		if unlock > 0 {
			fmt.Fprintf(&fb, "unlock_time = %d\n", unlock)
		}
		// Le compte root est explicitement exclu du verrouillage. Un attaquant
		// n'a besoin que de N tentatives ratées sur root pour supprimer le
		// dernier accès de secours d'une machine : le verrouillage deviendrait
		// alors une arme plutôt qu'une protection.
		fb.WriteString("even_deny_root = no\n")

		previous, had := readFileIfExists(faillockDropIn)
		if err := writeSystemFile(faillockDropIn, fb.String(), 0o644); err != nil {
			return "", err
		}
		if unlock == 0 {
			restoreOrRemove(faillockDropIn, previous, had)
			return "", fmt.Errorf(
				"verrouillage sans deverrouillage automatique refuse : une serie d'echecs volontaires bloquerait durablement des comptes legitimes, sans intervention possible a distance")
		}
		applied = append(applied, fmt.Sprintf("verrouillage apres %d echecs, %ds", deny, unlock))
	}

	if len(applied) == 0 {
		return "aucun parametre fourni, rien a appliquer", nil
	}
	return strings.Join(applied, " ; "), nil
}

// ---------------------------------------------------------------------------
// Politique des comptes locaux (local_account_policy)
// ---------------------------------------------------------------------------

// systemUIDCeiling est la frontière sous laquelle un compte est considéré comme
// un compte système.
//
// root (0) et les comptes de service vivent en dessous. Les toucher couperait
// des services, et pour root le dernier accès de secours à la machine.
const systemUIDCeiling = 1000

// applyLocalAccountPolicy applique une politique aux comptes locaux non-Vaultaire.
func applyLocalAccountPolicy(ctx Context, m Module) (string, error) {
	if m.Param("state") == "absent" {
		return "politique non appliquee (state=absent) : les comptes deja modifies ne sont pas restaures", nil
	}

	accounts, err := localNonVaultaireAccounts()
	if err != nil {
		return "", err
	}
	if len(accounts) == 0 {
		return "aucun compte local non-Vaultaire hors comptes systeme", nil
	}

	action := m.Param("action")
	if action == "report_only" {
		// Mode d'observation : on ne modifie rien. Sur un parc hétérogène, la
		// liste des comptes concernés est rarement celle qu'on imagine, et la
		// découvrir après coup se paie en comptes cassés.
		return fmt.Sprintf("mode observation — %d compte(s) concerne(s) : %s",
			len(accounts), strings.Join(accounts, ", ")), nil
	}

	maxAge := intParam(m, "max_age_days")
	inactive := intParam(m, "inactive_days")

	var touched []string
	for _, account := range accounts {
		switch action {
		case "lock_password":
			if _, err := runCommand("usermod", "-L", account); err != nil {
				return "", fmt.Errorf("verrouillage de %s impossible : %v", account, err)
			}
		case "expire":
			if _, err := runCommand("chage", "-E", "1", account); err != nil {
				return "", fmt.Errorf("expiration de %s impossible : %v", account, err)
			}
		}
		if maxAge > 0 {
			if _, err := runCommand("chage", "-M", strconv.Itoa(maxAge), account); err != nil {
				return "", fmt.Errorf("age maximal de %s impossible : %v", account, err)
			}
		}
		if inactive > 0 {
			if _, err := runCommand("chage", "-I", strconv.Itoa(inactive), account); err != nil {
				return "", fmt.Errorf("inactivite de %s impossible : %v", account, err)
			}
		}

		// L'attente, compte par compte et facette par facette.
		//
		// Le déverrouillage d'un compte local — un `usermod -U` fait à la main,
		// ou par un outil de dépannage — rendait au poste un accès que la
		// politique avait fermé, sans laisser aucune trace.
		//
		// « expire » n'est PAS revérifié : `chage -E 1` fixe une date passée, et
		// la relire supposerait de comparer des dates dans une sortie localisée.
		// Une vérification approximative déclarerait conforme ce qui ne l'est
		// pas ; mieux vaut ne rien affirmer sur cette facette-là.
		var attentes []string
		if action == "lock_password" {
			attentes = append(attentes, "locked=yes")
		}
		if maxAge > 0 {
			attentes = append(attentes, "max="+strconv.Itoa(maxAge))
		}
		if inactive > 0 {
			attentes = append(attentes, "inactive="+strconv.Itoa(inactive))
		}
		if len(attentes) > 0 {
			recordCheck(CheckAccountLock, account, strings.Join(attentes, ","))
		}

		touched = append(touched, account)
	}
	return fmt.Sprintf("%s applique a %d compte(s) : %s",
		action, len(touched), strings.Join(touched, ", ")), nil
}

// localNonVaultaireAccounts liste les comptes locaux hors comptes système et
// hors comptes créés par Vaultaire.
//
// Les comptes Vaultaire portent le commentaire GECOS « vaultaire_user_account »,
// posé par le module PAM à la création (voir pam_common.c). C'est ce marqueur
// qui permet de les distinguer sans interroger l'annuaire — la machine peut être
// hors ligne au moment où la politique s'applique.
func localNonVaultaireAccounts() ([]string, error) {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, fmt.Errorf("lecture de /etc/passwd impossible : %v", err)
	}
	defer func() { _ = file.Close() }()

	var accounts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) < 7 {
			continue
		}
		name, gecos, shell := fields[0], fields[4], fields[6]

		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid < systemUIDCeiling {
			continue
		}
		if strings.Contains(gecos, "vaultaire_user_account") {
			continue
		}
		// Un compte déjà sans shell interactif n'a rien à gagner à être
		// verrouillé, et le toucher brouillerait le rapport.
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "false") {
			continue
		}
		accounts = append(accounts, name)
	}
	return accounts, scanner.Err()
}

// ---------------------------------------------------------------------------
// Module noyau interdit (kernel_module_policy)
// ---------------------------------------------------------------------------

// applyKernelModulePolicy interdit le chargement d'un module noyau.
func applyKernelModulePolicy(ctx Context, m Module) (string, error) {
	name := m.Param("module")
	if name == "" {
		return "", fmt.Errorf("nom de module manquant")
	}
	path := "/etc/modprobe.d/vaultaire-" + name + ".conf"

	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(path); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", path, err)
		}
		return "interdiction de " + name + " levee", nil
	}

	// Les deux directives sont nécessaires et ne font pas la même chose :
	// « blacklist » empêche le chargement automatique par détection matérielle,
	// « install ... /bin/true » empêche aussi le chargement explicite par
	// modprobe. La première seule laisse un utilisateur privilégié charger le
	// module à la main.
	content := "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
		"blacklist " + name + "\n" +
		"install " + name + " /bin/true\n"
	if err := writeSystemFile(path, content, 0o644); err != nil {
		return "", err
	}

	detail := "chargement de " + name + " interdit"
	if m.Param("unload_now") == "true" {
		if _, err := runCommand("modprobe", "-r", name); err != nil {
			// Un module en cours d'utilisation ne se décharge pas. Ce n'est pas
			// un échec du module : l'interdiction est écrite et vaudra au
			// prochain démarrage.
			detail += " (dechargement immediat impossible, effectif au redemarrage)"
		} else {
			detail += " et decharge"
		}
	}
	return detail, nil
}

// ---------------------------------------------------------------------------
// Serveurs SSH connus (ssh_known_hosts)
// ---------------------------------------------------------------------------

const (
	knownHostsPath   = "/etc/ssh/ssh_known_hosts"
	sshClientDropIn  = "/etc/ssh/ssh_config.d/99-vaultaire-gpo.conf"
	knownHostsMarker = "# vaultaire-gpo:"
)

// applySSHKnownHosts pré-remplit la liste de confiance SSH de la machine.
func applySSHKnownHosts(ctx Context, m Module) (string, error) {
	host := m.Param("host")
	if host == "" {
		return "", fmt.Errorf("hote manquant")
	}

	existing, _ := readFileIfExists(knownHostsPath)
	marker := knownHostsMarker + host

	// Les lignes Vaultaire sont balisées par un commentaire portant l'hôte : on
	// peut ainsi retirer ou remplacer LA nôtre sans toucher aux entrées ajoutées
	// à la main par un administrateur, qui n'ont pas de balise.
	var kept []string
	skipNext := false
	for _, line := range strings.Split(existing, "\n") {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), marker) {
			skipNext = true
			continue
		}
		kept = append(kept, line)
	}
	rebuilt := strings.TrimRight(strings.Join(kept, "\n"), "\n")

	if m.Param("state") == "absent" {
		if rebuilt == "" {
			if _, err := removeSystemFile(knownHostsPath); err != nil {
				return "", err
			}
			return "hote " + host + " retire (fichier vide supprime)", nil
		}
		if err := writeSystemFile(knownHostsPath, rebuilt+"\n", 0o644); err != nil {
			return "", err
		}
		return "hote " + host + " retire", nil
	}

	key := strings.TrimSpace(m.RawParam("key"))
	if key == "" {
		return "", fmt.Errorf("cle publique du serveur manquante")
	}
	if strings.Contains(key, "\n") {
		return "", fmt.Errorf("la cle doit tenir sur une seule ligne")
	}

	if rebuilt != "" {
		rebuilt += "\n"
	}
	rebuilt += marker + "\n" + host + " " + key + "\n"
	if err := writeSystemFile(knownHostsPath, rebuilt, 0o644); err != nil {
		return "", err
	}
	detail := "hote " + host + " ajoute aux serveurs connus"

	if strict := m.Param("strict_host_key_checking"); strict != "" && strict != "unchanged" {
		content := "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
			"Host *\n    StrictHostKeyChecking " + strict + "\n"
		if err := writeSystemFile(sshClientDropIn, content, 0o644); err != nil {
			return "", err
		}
		detail += ", StrictHostKeyChecking=" + strict
	}
	return detail, nil
}

// ---------------------------------------------------------------------------
// Règle d'audit (auditd_rule)
// ---------------------------------------------------------------------------

// applyAuditdRule pose une règle de surveillance de chemin.
func applyAuditdRule(ctx Context, m Module) (string, error) {
	path := m.Param("path")
	key := m.Param("key")
	if path == "" || key == "" {
		return "", fmt.Errorf("chemin ou etiquette manquant")
	}
	file := "/etc/audit/rules.d/99-vaultaire-" + key + ".rules"

	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(file); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", file, err)
		}
		reloadAuditRules()
		return "regle d'audit " + key + " retiree", nil
	}

	// La règle est CONSTRUITE à partir des champs, jamais fournie en syntaxe
	// auditctl brute. auditd accepte des règles capables de désactiver l'audit
	// lui-même ou de saturer le journal : laisser passer une chaîne libre
	// reviendrait à accepter un langage complet depuis le réseau.
	rule := fmt.Sprintf("-w %s -p %s -k %s\n", path, m.Param("permissions"), key)
	content := "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" + rule

	previous, had := readFileIfExists(file)
	if err := writeSystemFile(file, content, 0o640); err != nil {
		return "", err
	}
	if err := reloadAuditRules(); err != nil {
		restoreOrRemove(file, previous, had)
		_ = reloadAuditRules()
		return "", fmt.Errorf("regle refusee par auditd, etat precedent restaure : %v", err)
	}
	return "audit de " + path + " (" + m.Param("permissions") + ", cle " + key + ")", nil
}

// reloadAuditRules recharge les règles d'audit.
func reloadAuditRules() error {
	if commandExists("augenrules") {
		if _, err := runCommand("augenrules", "--load"); err != nil {
			return err
		}
		return nil
	}
	if commandExists("auditctl") {
		_, err := runCommand("auditctl", "-R", "/etc/audit/audit.rules")
		return err
	}
	// auditd absent : la règle est écrite et prendra effet à son installation.
	return nil
}

// ---------------------------------------------------------------------------
// Mode SELinux (selinux_mode)
// ---------------------------------------------------------------------------

// applySELinuxMode fixe le mode SELinux et, éventuellement, un booléen.
func applySELinuxMode(ctx Context, m Module) (string, error) {
	if !commandExists("getenforce") {
		return "", fmt.Errorf("SELinux absent de cette machine")
	}

	var applied []string

	if mode := m.Param("mode"); mode != "" && mode != "unchanged" {
		current, _ := runCommand("getenforce")
		current = strings.ToLower(strings.TrimSpace(current))

		if mode == "enforcing" && current != "enforcing" {
			// REFUS du passage en enforcing sans réétiquetage préalable.
			//
			// Sur un système resté longtemps en permissive, des fichiers créés
			// entre-temps portent une étiquette absente ou fausse. Passer en
			// enforcing les rend inaccessibles à leurs services — sshd compris.
			// La machine devient alors injoignable, donc impossible à corriger
			// à distance : c'est exactement la panne que le mode permissive
			// existe pour éviter.
			if _, err := os.Stat("/.autorelabel"); err == nil {
				return "", fmt.Errorf(
					"passage en enforcing refuse : un reetiquetage est en attente (/.autorelabel), redemarrez d'abord la machine")
			}
			if !selinuxRelabelDone() {
				return "", fmt.Errorf(
					"passage en enforcing refuse : ce systeme n'a jamais ete reetiquete depuis SELinux permissive. " +
						"Lancez « touch /.autorelabel && reboot » sur la machine, puis reappliquez la politique")
			}
		}

		if _, err := runCommand("setenforce", map[string]string{"enforcing": "1", "permissive": "0"}[mode]); err != nil {
			return "", fmt.Errorf("changement de mode impossible : %v", err)
		}
		// Le mode courant ne survit pas au redémarrage : il faut aussi écrire
		// la configuration persistante.
		if err := setSELinuxConfigMode(mode); err != nil {
			_, _ = runCommand("setenforce", map[string]string{"enforcing": "0", "permissive": "1"}[mode])
			return "", fmt.Errorf("mode persistant non ecrit, mode courant restaure : %v", err)
		}
		recordCheck(CheckSELinux, "mode", mode)
		applied = append(applied, "mode "+mode)
	}

	if name := m.Param("boolean_name"); name != "" {
		value := m.Param("boolean_value")
		if value != "" && value != "unchanged" {
			if _, err := runCommand("setsebool", "-P", name, value); err != nil {
				return "", fmt.Errorf("booleen %s impossible : %v", name, err)
			}
			recordCheck(CheckSELinux, "bool:"+name, value)
			applied = append(applied, name+"="+value)
		}
	}

	if len(applied) == 0 {
		return "aucun changement demande", nil
	}
	return strings.Join(applied, ", "), nil
}

// selinuxRelabelDone dit si le système porte les traces d'un réétiquetage.
//
// La présence de /etc/selinux/.rebootflag ou d'un contexte cohérent sur /etc
// indique qu'un relabel a eu lieu. Le test est volontairement conservateur :
// dans le doute on refuse le passage en enforcing, parce que se tromper dans ce
// sens coûte un aller-retour, tandis que se tromper dans l'autre coûte une
// machine injoignable.
func selinuxRelabelDone() bool {
	out, err := runCommand("ls", "-Zd", "/etc")
	if err != nil {
		return false
	}
	return strings.Contains(out, "etc_t")
}

// setSELinuxConfigMode écrit le mode dans /etc/selinux/config.
func setSELinuxConfigMode(mode string) error {
	const path = "/etc/selinux/config"
	content, ok := readFileIfExists(path)
	if !ok {
		return fmt.Errorf("%s introuvable", path)
	}

	var out []string
	replaced := false
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "SELINUX=") &&
			!strings.HasPrefix(strings.TrimSpace(line), "SELINUXTYPE=") {
			out = append(out, "SELINUX="+mode)
			replaced = true
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append(out, "SELINUX="+mode)
	}
	return writeSystemFile(path, strings.Join(out, "\n"), 0o644)
}

// intParam lit un paramètre entier, 0 si absent ou illisible.
func intParam(m Module, name string) int {
	value, err := strconv.Atoi(m.Param(name))
	if err != nil {
		return 0
	}
	return value
}
