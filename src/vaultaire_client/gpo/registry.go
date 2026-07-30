package gpo

import (
	"context"
	"fmt"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Registre des appliqueurs de modules.
//
// POINT D'EXTENSION — ajouter un module se fait en deux lignes :
//  1. écrire la fonction d'application dans un fichier appliers_*.go ;
//  2. l'enregistrer dans appliers ci-dessous.
//
// Le moteur (apply.go) n'a pas à changer, et un module envoyé par un serveur
// plus récent que l'agent est rapporté « skipped » avec sa raison — jamais
// ignoré en silence.

// appliers associe un type de module à son appliqueur.
var appliers = map[string]Applier{
	ModuleSSHServerConfig: applySSHServerConfig,
	ModuleSysctl:          applySysctl,
	ModuleSudoersRule:     applySudoersRule,
	ModulePackage:         applyPackage,
	ModuleSystemdService:  applySystemdService,
	ModuleFileDeploy:      applyFileDeploy,
	ModuleUserEnv:         applyUserEnv,
	ModuleUserCron:        applyUserCron,
}

// ApplierFor retourne l'appliqueur d'un type de module.
func ApplierFor(moduleType string) (Applier, bool) {
	applier, ok := appliers[moduleType]
	return applier, ok
}

// SupportedModuleTypes retourne les types que cet agent sait appliquer.
func SupportedModuleTypes() []string {
	out := make([]string, 0, len(appliers))
	for t := range appliers {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Utilitaires partagés par les appliqueurs
// ---------------------------------------------------------------------------

// vaultaireMarkerStart et vaultaireMarkerEnd délimitent les blocs gérés par
// Vaultaire à l'intérieur d'un fichier qui ne lui appartient pas entièrement.
// Écraser un tel fichier détruirait la configuration locale de l'administrateur.
const (
	vaultaireMarkerStart = "# >>> vaultaire gpo start <<<"
	vaultaireMarkerEnd   = "# >>> vaultaire gpo end <<<"
)

// managedBlock encadre un contenu par les marqueurs Vaultaire.
func managedBlock(content string) string {
	return vaultaireMarkerStart + "\n" +
		"# Bloc gere par Vaultaire. Toute modification manuelle sera ecrasee.\n" +
		strings.TrimRight(content, "\n") + "\n" +
		vaultaireMarkerEnd + "\n"
}

// replaceManagedBlock remplace le bloc Vaultaire d'un contenu, ou l'ajoute.
func replaceManagedBlock(existing, content string) string {
	block := managedBlock(content)

	start := strings.Index(existing, vaultaireMarkerStart)
	if start == -1 {
		if strings.TrimSpace(existing) == "" {
			return block
		}
		return strings.TrimRight(existing, "\n") + "\n\n" + block
	}

	end := strings.Index(existing[start:], vaultaireMarkerEnd)
	if end == -1 {
		// Marqueur d'ouverture sans fermeture : fichier tronqué ou édité à la
		// main. On remplace jusqu'à la fin plutôt que de laisser un bloc ouvert
		// qui absorberait le reste du fichier au prochain passage.
		return existing[:start] + block
	}
	end = start + end + len(vaultaireMarkerEnd)
	tail := existing[end:]
	tail = strings.TrimLeft(tail, "\n")
	if tail != "" {
		return existing[:start] + block + "\n" + tail
	}
	return existing[:start] + block
}

// Délais maximaux d'exécution des commandes système.
//
// Aucune commande ne doit pouvoir bloquer indéfiniment : celles du scope
// utilisateur s'exécutent sur le chemin d'ouverture de session, et
// « systemctl --user » attend le bus de l'utilisateur, qui peut ne pas être
// démarré. Sans borne, une session se figerait sans explication.
const (
	// DefaultCommandTimeout couvre les opérations machine, installation de
	// paquets comprise.
	DefaultCommandTimeout = 5 * time.Minute
	// UserCommandTimeout couvre les opérations du scope utilisateur, sur le
	// chemin de connexion.
	UserCommandTimeout = 10 * time.Second
)

// runCommand exécute une commande système et retourne sa sortie combinée.
//
// Les commandes exécutées ici ne viennent JAMAIS de la politique : elles sont
// écrites en dur dans les appliqueurs. La politique ne fournit que des valeurs,
// passées en arguments distincts — jamais interprétées par un shell.
func runCommand(name string, args ...string) (string, error) {
	return runCommandTimeout(DefaultCommandTimeout, name, args...)
}

// runCommandTimeout exécute une commande avec un délai maximal.
func runCommandTimeout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))

	if ctx.Err() == context.DeadlineExceeded {
		return trimmed, fmt.Errorf("%s %s : delai de %s depasse", name, strings.Join(args, " "), timeout)
	}
	if err != nil {
		if trimmed != "" {
			return trimmed, fmt.Errorf("%s %s : %v (%s)", name, strings.Join(args, " "), err, trimmed)
		}
		return trimmed, fmt.Errorf("%s %s : %v", name, strings.Join(args, " "), err)
	}
	return trimmed, nil
}

// commandExists indique si un binaire est disponible dans le PATH.
func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// resolveHomeDir retourne le home réel d'un utilisateur local.
func resolveHomeDir(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("utilisateur local %s introuvable : %v", username, err)
	}
	if strings.TrimSpace(u.HomeDir) == "" {
		return "", fmt.Errorf("utilisateur local %s sans repertoire personnel", username)
	}
	return u.HomeDir, nil
}

// resolveUserIDs retourne l'uid et le gid d'un utilisateur local.
func resolveUserIDs(username string) (int, int, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return 0, 0, fmt.Errorf("utilisateur local %s introuvable : %v", username, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("uid illisible pour %s : %v", username, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("gid illisible pour %s : %v", username, err)
	}
	return uid, gid, nil
}

// expandHome remplace le marqueur %h par le home réel.
//
// Le marqueur est le seul chemin autorisé en scope user côté serveur : si un
// chemin arrive sans lui dans ce scope, c'est une incohérence et on refuse
// plutôt que d'écrire à un emplacement système.
func expandHome(ctx Context, path string) (string, error) {
	if ctx.Scope != ScopeUser {
		return path, nil
	}
	if !strings.HasPrefix(path, UserHomePlaceholder+"/") {
		return "", fmt.Errorf("chemin user hors du marqueur %s : %s", UserHomePlaceholder, path)
	}
	if ctx.HomeDir == "" {
		return "", fmt.Errorf("home de l'utilisateur non resolu")
	}
	return ctx.HomeDir + strings.TrimPrefix(path, UserHomePlaceholder), nil
}

// parseFileMode interprète des permissions octales à trois chiffres.
func parseFileMode(raw string) (uint32, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return 0o644, nil
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "0"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("permissions %q invalides : %v", raw, err)
	}
	// Les bits setuid/setgid/sticky ne sont pas exprimables : le serveur
	// n'accepte que trois chiffres, on refuse ici aussi par défense en profondeur.
	if parsed > 0o777 {
		return 0, fmt.Errorf("permissions %q hors des trois chiffres autorises", raw)
	}
	return uint32(parsed), nil
}
