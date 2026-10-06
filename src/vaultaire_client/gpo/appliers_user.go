package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Appliqueurs des modules de scope utilisateur, plus le déploiement de fichier
// qui vaut dans les deux scopes.
//
// Tout ce qui est écrit ici appartient à l'utilisateur cible, jamais à root :
// les fichiers sont créés puis rattachés à son uid/gid. Un fichier appartenant à
// root dans le home d'un utilisateur l'empêcherait de le modifier et
// ressemblerait à une panne inexplicable de son côté.

// userEnvFileName est le fichier, appartenant à Vaultaire, qui porte les
// variables. Les fichiers de démarrage du shell ne contiennent qu'une ligne de
// sourcing vers lui : ainsi une variable retirée d'une GPO disparaît en
// réécrivant ce seul fichier, sans retoucher aux fichiers de l'utilisateur.
const userEnvFileName = ".vaultaire_env"

// legacyProfileHook est un fichier créé par une version antérieure de cet
// agent. Il contenait l'instruction de sourcing... mais aucun shell ne lit un
// fichier de ce nom : la variable était bien écrite et jamais chargée. On le
// supprime au passage pour ne pas laisser un fichier trompeur dans les homes.
const legacyProfileHook = ".profile.d-vaultaire"

// shellStartupFiles liste les fichiers de démarrage susceptibles de charger
// l'environnement d'une session.
//
// Vaultaire n'y écrit qu'un bloc délimité par ses marqueurs, jamais le fichier
// entier : ces fichiers appartiennent à l'utilisateur et contiennent sa propre
// configuration. C'est la différence avec le module file_deploy, à qui le
// serveur interdit ces chemins — lui remplacerait tout le contenu.
//
// Plusieurs fichiers plutôt qu'un seul, parce qu'aucun n'est garanti :
// bash lit .bash_profile s'il existe, sinon .bash_login, sinon .profile, et
// .bashrc pour les shells interactifs non-login. Poser le bloc dans chacun de
// ceux qui existent couvre les cas sans avoir à deviner la distribution ni le
// shell. Sourcer deux fois le même fichier est sans effet de bord : il ne
// contient que des export.
var shellStartupFiles = []string{".bashrc", ".bash_profile", ".profile", ".zshrc"}

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

	// Le fichier est ÉCRIT DEPUIS LA POLITIQUE, sans relire ce qu'il contient —
	// TO-DO 135.
	//
	// # Ce que faisait la version précédente
	//
	// Elle relisait le fichier, remplaçait SA ligne et recopiait les autres,
	// pour que les variables des modules voisins survivent. Trois conséquences,
	// dont deux n'apparaissent qu'avec l'inventaire :
	//
	//   - une ligne ajoutée à la main survivait à toutes les réapplications, et
	//     entrait dans le hachage attendu : la « correction » d'une dérive
	//     consacrait ce qu'elle devait effacer ;
	//   - une variable retirée de la politique restait dans le fichier pour
	//     toujours, alors que le commentaire de userEnvFileName promet l'inverse ;
	//   - la relecture passait par `os.ReadFile`, qui suit les liens : root
	//     recopiait la cible d'un lien planté là dans un fichier appartenant à
	//     l'utilisateur.
	//
	// Le contenu ne dépend plus que de la politique : n'importe lequel des
	// modules `user_env` produit le fichier entier, et tous produisent le même.
	// Ils en répondent ensemble (FileState.Owners), et un écart les fait rejouer.
	content := "# Fichier genere par Vaultaire GPO. Ne pas editer a la main.\n" +
		strings.Join(lignesDEnvironnement(ctx, name, value), "\n") + "\n"

	if err := writeUserFile(ctx, envPath, content, 0o644); err != nil {
		return "", err
	}
	hooked, err := ensureProfileHook(ctx, envPath)
	if err != nil {
		return "", err
	}

	// Le détail mentionne les fichiers accrochés, et pas seulement « défini » :
	// la version précédente écrivait bien la variable et rapportait un succès,
	// alors que rien ne la chargeait. Un rapport qui ne distingue pas « écrit »
	// de « effectif » ne sert à rien pour diagnostiquer.
	return fmt.Sprintf("%s defini pour %s (charge depuis %s)",
		name, ctx.Username, strings.Join(hooked, ", ")), nil
}

// ensureProfileHook fait charger le fichier d'environnement par le shell.
//
// Retourne les fichiers de démarrage effectivement accrochés.
func ensureProfileHook(ctx Context, envPath string) ([]string, error) {
	// Forme « if ... fi » et non « [ -r x ] && . x » : cette dernière renvoie un
	// code non nul quand le fichier est absent, ce qui ferait échouer le
	// .bashrc entier s'il s'agit de sa dernière instruction.
	block := fmt.Sprintf("if [ -r %s ]; then . %s; fi", shellQuote(envPath), shellQuote(envPath))

	var hooked, ecartes []string
	for _, name := range shellStartupFiles {
		path := filepath.Join(ctx.HomeDir, name)
		// Lecture SANS suivre de lien — voir lireFichierUtilisateur. Un fichier
		// de démarrage qui est un lien symbolique, ou qui n'appartient pas au
		// compte, est laissé tel quel : ni lu, ni remplacé. L'ancien code lisait
		// à travers le lien puis écrasait le lien par un fichier ordinaire, ce
		// qui recopiait la cible chez l'utilisateur et défaisait au passage le
		// rangement de qui tient ses fichiers de démarrage sous un gestionnaire.
		existing, exists, err := readUserFile(ctx, path)
		if err != nil {
			ecartes = append(ecartes, name)
			logs.Write_log("WARNING", fmt.Sprintf(
				"GPO: %s de %s laisse tel quel, il n'est pas un fichier ordinaire du compte : %v",
				name, ctx.Username, err))
			continue
		}
		if !exists {
			continue
		}
		if err := writeUserBlock(ctx, path, replaceManagedBlock(existing, block), 0o644, blocEnvironnement); err != nil {
			return nil, fmt.Errorf("accrochage dans %s impossible : %v", name, err)
		}
		hooked = append(hooked, name)
	}

	// Aucun fichier de démarrage : home fraîchement créé sans squelette. On crée
	// .bashrc, lu par les shells interactifs et sourcé par le .bash_profile de
	// la plupart des distributions.
	if len(hooked) == 0 {
		// Sauf si .bashrc EXISTE et vient d'être écarté : le créer reviendrait à
		// le remplacer, c'est-à-dire à faire ce que la lecture vient de refuser.
		for _, name := range ecartes {
			if name == ".bashrc" {
				return nil, fmt.Errorf(
					"aucun fichier de demarrage accrochable : %s existe(nt) mais ce ne sont pas "+
						"des fichiers ordinaires du compte (lien symbolique ?)", strings.Join(ecartes, ", "))
			}
		}
		path := filepath.Join(ctx.HomeDir, ".bashrc")
		if err := writeUserBlock(ctx, path, replaceManagedBlock("", block), 0o644, blocEnvironnement); err != nil {
			return nil, fmt.Errorf("creation de .bashrc impossible : %v", err)
		}
		hooked = append(hooked, ".bashrc")
	}

	// Nettoyage du fichier inerte créé par la version précédente. Par la
	// descente sûre, et sans rien inscrire : ce n'est pas une politique, c'est
	// du ménage.
	if uid, _, err := resolveUserIDs(ctx.Username); err == nil {
		_, _ = retirerSousHome(ctx.HomeDir, filepath.Join(ctx.HomeDir, legacyProfileHook), uid)
	}

	return hooked, nil
}

// lignesDEnvironnement rend les lignes « export » de TOUTES les variables que
// la politique en cours pose pour ce compte.
//
// L'ordre est celui de la politique, donc celui de l'application. Deux modules
// qui posent la même variable : le dernier l'emporte, comme il l'emporterait
// s'ils écrivaient l'un après l'autre.
//
// Le module en cours est ajouté s'il manque — c'est le cas d'un test qui
// appelle l'appliqueur à la main, sans politique autour.
func lignesDEnvironnement(ctx Context, nom, valeur string) []string {
	var noms []string
	valeurs := map[string]string{}
	poser := func(n, v string) {
		if n == "" {
			return
		}
		if _, deja := valeurs[n]; !deja {
			noms = append(noms, n)
		}
		valeurs[n] = v
	}

	if ctx.Politique != nil {
		for _, m := range ctx.Politique.Modules {
			if m.Type != ModuleUserEnv {
				continue
			}
			poser(strings.ToUpper(m.Param("name")), m.Param("value"))
		}
	}
	if _, present := valeurs[nom]; !present {
		poser(nom, valeur)
	}

	lignes := make([]string, 0, len(noms))
	for _, n := range noms {
		lignes = append(lignes, "export "+n+"="+shellQuote(valeurs[n]))
	}
	return lignes
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
			if existait, err := removeUserFile(ctx, path); err == nil && existait {
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
		// Sous un `HOME`, le retrait passe par la descente sûre : `os.Remove`
		// résout les répertoires intermédiaires, et un lien planté à la place
		// de l'un d'eux faisait supprimer par root un fichier hors du dossier.
		var existait bool
		if ctx.Scope == ScopeUser {
			existait, err = removeUserFile(ctx, path)
		} else {
			existait, err = ctx.removeSystemFile(path)
		}
		if err != nil {
			return "", fmt.Errorf("suppression de %s impossible : %v", path, err)
		}
		if !existait {
			return path + " deja absent", nil
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

	if err := ctx.writeSystemFile(path, content, os.FileMode(mode)); err != nil {
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
//
// # Ce que cette fonction faisait, et pourquoi c'était une élévation vers root
//
// Elle appelait `os.MkdirAll`, `chownTree` puis `os.Chown` — trois fonctions qui
// DÉRÉFÉRENCENT les liens symboliques —, et `chownTree` vérifiait l'appartenance
// au `HOME` par `strings.HasPrefix` sur la chaîne non résolue.
//
// Elle tourne EN ROOT, lancée par PAM, sur un dossier que l'utilisateur
// contrôle. Il lui suffisait de remplacer un répertoire intermédiaire par un
// lien vers `/etc` pour que root chowne `/etc` à son nom. Voir TO-DO 97 et
// chemin_sur_linux.go, qui porte le détail complet du chemin d'attaque.
//
// La traversée passe désormais par des DESCRIPTEURS : chaque composant est
// ouvert relativement au précédent avec `O_NOFOLLOW`, et l'écriture comme le
// changement de propriétaire se font sur le descripteur, jamais sur un chemin
// qu'il faudrait résoudre une seconde fois.
//
// `chownTree` a disparu : la descente pose elle-même le propriétaire des
// répertoires qu'elle crée, ce qui était sa seule raison d'être.
//
// # Et il entre dans l'inventaire — TO-DO 135
//
// C'est la ligne qui manquait. `writeSystemFile` inscrivait ce qu'il écrivait ;
// cette fonction, non. Les fichiers d'un `HOME` n'entraient donc JAMAIS dans
// l'inventaire, le scan de conformité sortait sur « rien à comparer » sans
// émettre de rapport, et un fichier supprimé ou réécrit par l'utilisateur
// restait affiché conforme — indéfiniment, puisque le cycle suivant recevait
// « politique inchangée » et ne posait rien.
//
// Le chemin inscrit est le chemin RÉSOLU, `%h` développé : c'est celui que le
// scan relira. L'inscription suit l'écriture, comme côté machine : un fichier
// que le disque n'a pas reçu ne doit pas être surveillé.
//
// Cette fonction est pour un fichier qui appartient EN ENTIER à la politique.
// Un fichier de l'utilisateur dans lequel Vaultaire ne tient qu'un bloc passe
// par writeUserBlock : en hacher la totalité ferait signaler une dérive chaque
// fois que la personne édite son propre `.bashrc`.
func writeUserFile(ctx Context, path, content string, mode os.FileMode) error {
	uid, gid, err := idsDuCompte(ctx)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if err := ecrireFichierUtilisateur(ctx.HomeDir, path, content, mode, uid, gid); err != nil {
		return err
	}
	ctx.inventaire().noterEcriture(path, content, mode)
	return nil
}

// idsDuCompte résout l'uid et le gid du compte cible.
func idsDuCompte(ctx Context) (int, int, error) {
	if ctx.Username == "" {
		return 0, 0, fmt.Errorf("utilisateur cible non defini")
	}
	return resolveUserIDs(ctx.Username)
}

// removeUserFile retire un fichier — ou un répertoire vide — sous le `HOME`, et
// inscrit qu'il doit rester absent.
//
// Le pendant de removeSystemFile pour le scope utilisateur, avec deux
// différences qui sont toute sa raison d'être : la traversée ne suit aucun lien
// (voir retirerSousHome), et l'absence est inscrite dans l'inventaire du cycle
// de CE compte.
func removeUserFile(ctx Context, path string) (bool, error) {
	uid, _, err := idsDuCompte(ctx)
	if err != nil {
		return false, err
	}
	path = filepath.Clean(path)
	existait, err := retirerSousHome(ctx.HomeDir, path, uid)
	if err != nil {
		// Rien n'est inscrit : la politique n'a pas abouti, et surveiller une
		// absence jamais obtenue signalerait une dérive permanente.
		return false, err
	}
	ctx.inventaire().noterAbsence(path)
	return existait, nil
}

// readUserFile lit un fichier sous le `HOME` du compte, sans suivre de lien.
func readUserFile(ctx Context, path string) (string, bool, error) {
	uid, _, err := idsDuCompte(ctx)
	if err != nil {
		return "", false, err
	}
	return lireFichierUtilisateur(ctx.HomeDir, filepath.Clean(path), uid)
}

// writeUserBlock écrit un fichier de l'UTILISATEUR dans lequel Vaultaire tient
// un bloc, et inscrit ce bloc — pas le fichier.
//
// # Pourquoi pas le fichier entier
//
// `.bashrc`, `.profile`, `~/.ssh/config` appartiennent à la personne. La
// politique n'y demande qu'une chose : que SON bloc y soit, tel qu'elle l'a
// écrit. Hacher le fichier ferait de chaque alias ajouté par l'utilisateur une
// dérive, corrigée — c'est-à-dire réécrite — à la connexion suivante, et la vue
// de conformité se remplirait de comptes « en écart » parce qu'ils se servent
// de leur shell.
//
// Ce qui est inscrit est donc une ATTENTE (CheckFileBlock) sur le contenu du
// bloc : la retirer ou la modifier est un écart, tout le reste du fichier est
// hors du champ. Un bloc que le contenu écrit ne porte pas — parce que la
// politique le retire — s'inscrit comme devant rester absent.
func writeUserBlock(ctx Context, path, content string, mode os.FileMode, bloc string) error {
	uid, gid, err := idsDuCompte(ctx)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if err := ecrireFichierUtilisateur(ctx.HomeDir, path, content, mode, uid, gid); err != nil {
		return err
	}
	inscrireBloc(ctx, path, content, bloc)
	return nil
}

// removeUserBlock retire le fichier où le bloc était SEUL, et inscrit que ce
// bloc doit rester absent.
//
// Ce n'est pas « ce fichier ne doit pas exister » : la politique ne demande que
// l'absence de son bloc, et la personne peut créer demain son propre fichier
// sans que ce soit un écart.
func removeUserBlock(ctx Context, path, bloc string) error {
	uid, _, err := idsDuCompte(ctx)
	if err != nil {
		return err
	}
	path = filepath.Clean(path)
	if _, err := retirerSousHome(ctx.HomeDir, path, uid); err != nil {
		return err
	}
	inscrireBloc(ctx, path, "", bloc)
	return nil
}

// inscrireBloc déclare ce que le bloc doit être, d'après ce qui vient d'être
// écrit.
//
// L'attente est tirée du CONTENU ÉCRIT, par la même extraction que celle du
// vérificateur : il est impossible que l'un cherche autre chose que ce que
// l'autre a posé.
//
// Le nom du compte voyage dans l'attente. Le vérificateur en a besoin pour
// relire le fichier par la descente sûre — qui exige le `HOME` et l'uid —, et
// il ne reçoit rien d'autre que l'attente.
func inscrireBloc(ctx Context, chemin, contenu, bloc string) {
	debut, fin, ok := marqueursDuBloc(bloc)
	if !ok {
		return
	}
	attendu := "compte=" + ctx.Username
	if corps, present := extraireBloc(contenu, debut, fin); present {
		attendu += ",sha256=" + hacherBloc(corps)
	} else {
		attendu += ",etat=absent"
	}
	ctx.recordCheck(CheckFileBlock, chemin+separateurBloc+bloc, attendu)
}

// shellQuote protège une valeur destinée à un fichier sourcé par le shell.
//
// La valeur vient d'une politique validée côté serveur, mais elle est écrite
// dans un fichier que le shell interprète : sans protection, une apostrophe
// suffirait à faire exécuter autre chose à l'ouverture de session.
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}
