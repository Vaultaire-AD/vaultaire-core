package gpo

import (
	"fmt"
	"os"
	"strings"
)

// Appliqueurs des phases « fichiers » et « sources ».
//
// Ces modules s'exécutent AVANT l'installation des paquets et le démarrage des
// services (voir l'ordre d'application dans core/gpo/registry.go côté serveur).
// C'est ce qui permet à une politique de déposer une configuration, de déclarer
// le dépôt d'où vient le logiciel, puis de l'installer et de le démarrer sur
// une configuration déjà correcte.

// ---------------------------------------------------------------------------
// Répertoire
// ---------------------------------------------------------------------------

// applyDirectory crée ou retire un répertoire.
func applyDirectory(ctx Context, m Module) (string, error) {
	path, err := expandHome(ctx, m.Param("path"))
	if err != nil {
		return "", err
	}

	if m.Param("state") == "absent" {
		// removeSystemFile s'appuie sur os.Remove et non RemoveAll : un
		// répertoire non vide n'est pas supprimé. Effacer récursivement depuis
		// une politique transformerait une faute de frappe dans un chemin en
		// perte de données, sur toutes les machines à la fois et sans
		// confirmation possible.
		//
		// L'absence est notée dans les deux cas — déjà absent ou retiré à
		// l'instant : la politique dit que ce chemin ne doit pas exister, et
		// c'est ce que le scan doit surveiller.
		existait, err := removeSystemFile(path)
		if err != nil {
			return "", fmt.Errorf("suppression de %s impossible (non vide ?) : %v", path, err)
		}
		if !existait {
			return "deja absent : " + path, nil
		}
		return "supprime : " + path, nil
	}

	mode, err := parseFileMode(m.Param("mode"))
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, os.FileMode(mode)); err != nil {
		return "", fmt.Errorf("creation de %s impossible : %v", path, err)
	}
	// MkdirAll n'applique le mode qu'aux répertoires qu'il crée : un répertoire
	// préexistant garderait ses permissions, et la politique serait annoncée
	// appliquée sans l'être.
	if err := os.Chmod(path, os.FileMode(mode)); err != nil {
		return "", fmt.Errorf("permissions de %s impossibles : %v", path, err)
	}

	detail := fmt.Sprintf("repertoire %s (%04o)", path, mode)
	// En scope user le répertoire appartient déjà à l'utilisateur cible : il est
	// créé sous son home. Forcer un propriétaire n'aurait de sens qu'en scope
	// machine, et le serveur refuse déjà d'autres chemins.
	if ctx.Scope != ScopeUser {
		if owner := m.Param("owner"); owner != "" {
			group := m.Param("group")
			if group == "" {
				group = owner
			}
			if commandExists("chown") {
				if _, err := runCommand("chown", owner+":"+group, path); err != nil {
					return "", fmt.Errorf("repertoire cree mais proprietaire non applique : %v", err)
				}
				detail += ", " + owner + ":" + group
			}
		}
	}
	return detail, nil
}

// ---------------------------------------------------------------------------
// Fichier avec substitution
// ---------------------------------------------------------------------------

// applyTemplatedFile dépose un fichier après substitution des marqueurs.
//
// Réutilise applyFileDeploy après substitution plutôt que de réimplémenter le
// dépôt : les deux modules doivent traiter les permissions, la propriété et
// l'écriture atomique exactement de la même façon, et deux implémentations
// finiraient par diverger sur un détail qui compte.
func applyTemplatedFile(ctx Context, m Module) (string, error) {
	substituted := m
	substituted.Params = make(map[string]string, len(m.Params))
	for k, v := range m.Params {
		substituted.Params[k] = v
	}
	substituted.Params["content"] = expandTemplate(ctx, m.RawParam("content"))

	detail, err := applyFileDeploy(ctx, substituted)
	if err != nil {
		return "", err
	}
	return detail + " (avec substitution)", nil
}

// expandTemplate remplace les marqueurs connus.
//
// Un marqueur INCONNU est laissé tel quel, jamais remplacé par du vide. Un
// fichier de configuration dont un champ aurait été silencieusement vidé reste
// syntaxiquement valide et devient faux : le service démarre et se comporte mal,
// ce qui est plus long à diagnostiquer qu'un marqueur resté visible dans le
// fichier.
func expandTemplate(ctx Context, content string) string {
	replacements := map[string]string{
		"{{hostname}}": ctx.Hostname,
		"{{fqdn}}":     ctx.FQDN,
		"{{username}}": ctx.Username,
		"{{domain}}":   ctx.Domain,
	}
	for marker, value := range replacements {
		if value == "" {
			// Valeur inconnue de l'agent : on laisse le marqueur plutôt que
			// d'écrire du vide, pour la même raison.
			continue
		}
		content = strings.ReplaceAll(content, marker, value)
	}
	return content
}

// ---------------------------------------------------------------------------
// Autorité de certification
// ---------------------------------------------------------------------------

// caStorePaths liste les emplacements du magasin de confiance selon la famille
// de distribution, avec la commande de régénération associée.
var caStorePaths = []struct {
	dir     string
	suffix  string
	refresh []string
}{
	{"/usr/local/share/ca-certificates", ".crt", []string{"update-ca-certificates"}},     // Debian/Ubuntu
	{"/etc/pki/ca-trust/source/anchors", ".pem", []string{"update-ca-trust", "extract"}}, // RHEL/Rocky
}

// applyTrustedCA installe ou retire une CA du magasin de confiance système.
func applyTrustedCA(ctx Context, m Module) (string, error) {
	name := strings.TrimSpace(m.Param("name"))
	if name == "" {
		return "", fmt.Errorf("nom de CA manquant")
	}

	store, ok := detectCAStore()
	if !ok {
		return "", fmt.Errorf("aucun magasin de confiance reconnu sur cette distribution")
	}
	path := store.dir + "/vaultaire-" + name + store.suffix

	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(path); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", path, err)
		}
		if _, err := runCommand(store.refresh[0], store.refresh[1:]...); err != nil {
			return "", err
		}
		return "CA " + name + " retiree du magasin", nil
	}

	cert := strings.TrimSpace(m.RawParam("certificate"))
	// Refus d'une clé privée. Le champ attend un certificat public ; y coller un
	// bloc PRIVATE KEY par erreur le diffuserait en clair sur tout le parc, dans
	// un répertoire lisible par tous.
	if strings.Contains(cert, "PRIVATE KEY") {
		return "", fmt.Errorf("le champ certificat contient une cle privee : refuse")
	}
	if !strings.Contains(cert, "BEGIN CERTIFICATE") {
		return "", fmt.Errorf("le champ certificat ne contient pas de bloc BEGIN CERTIFICATE")
	}

	if err := writeSystemFile(path, cert+"\n", 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand(store.refresh[0], store.refresh[1:]...); err != nil {
		// Le fichier est en place mais le magasin n'a pas été régénéré : la CA
		// n'est donc PAS encore reconnue. Retirer le fichier évite de laisser
		// croire à un succès partiel.
		os.Remove(path)
		return "", fmt.Errorf("regeneration du magasin de confiance impossible : %v", err)
	}
	return "CA " + name + " installee (" + store.dir + ")", nil
}

// detectCAStore retourne le magasin de confiance présent sur la machine.
func detectCAStore() (struct {
	dir     string
	suffix  string
	refresh []string
}, bool) {
	for _, store := range caStorePaths {
		if info, err := os.Stat(store.dir); err == nil && info.IsDir() {
			return store, true
		}
	}
	return caStorePaths[0], false
}

// ---------------------------------------------------------------------------
// Résolution DNS
// ---------------------------------------------------------------------------

// resolvedDropIn est le fichier de configuration systemd-resolved dédié.
//
// Un fichier séparé sous resolved.conf.d/, et surtout PAS /etc/resolv.conf :
// ce dernier est régénéré par systemd-resolved, NetworkManager ou le client
// DHCP selon les machines. Une politique qui l'écrirait directement serait
// effacée au premier renouvellement de bail, sans que rien ne le signale.
const resolvedDropIn = "/etc/systemd/resolved.conf.d/99-vaultaire-gpo.conf"

// applyDNSResolver fixe les serveurs DNS et le domaine de recherche.
func applyDNSResolver(ctx Context, m Module) (string, error) {
	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(resolvedDropIn); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", resolvedDropIn, err)
		}
		_, _ = runCommand("systemctl", "restart", "systemd-resolved")
		return "resolution DNS rendue a la configuration locale", nil
	}

	servers := normalizeList(m.Param("servers"))
	if servers == "" {
		return "", fmt.Errorf("aucun serveur DNS fourni")
	}

	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	b.WriteString("[Resolve]\n")
	b.WriteString("DNS=" + servers + "\n")
	if domains := normalizeList(m.Param("search_domain")); domains != "" {
		b.WriteString("Domains=" + domains + "\n")
	}

	previous, had := readFileIfExists(resolvedDropIn)
	if err := writeSystemFile(resolvedDropIn, b.String(), 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "restart", "systemd-resolved"); err != nil {
		// Restauration : une résolution DNS cassée coupe la machine du serveur
		// Vaultaire lui-même. Sans retour en arrière, plus aucune politique
		// corrective ne pourrait l'atteindre.
		restoreOrRemove(resolvedDropIn, previous, had)
		_, _ = runCommand("systemctl", "restart", "systemd-resolved")
		return "", fmt.Errorf("redemarrage de systemd-resolved impossible, configuration restauree : %v", err)
	}
	return "DNS = " + servers, nil
}

// normalizeList nettoie une liste séparée par des virgules et la rend séparée
// par des espaces, forme attendue par systemd.
func normalizeList(raw string) string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return strings.Join(out, " ")
}

// ---------------------------------------------------------------------------
// Dépôt de paquets
// ---------------------------------------------------------------------------

// applyPackageRepo déclare ou retire un dépôt de paquets.
func applyPackageRepo(ctx Context, m Module) (string, error) {
	name := strings.TrimSpace(m.Param("name"))
	if name == "" {
		return "", fmt.Errorf("nom de depot manquant")
	}

	manager, err := detectPackageManager()
	if err != nil {
		return "", err
	}
	apt := manager == "apt-get"

	path := "/etc/yum.repos.d/vaultaire-" + name + ".repo"
	if apt {
		path = "/etc/apt/sources.list.d/vaultaire-" + name + ".list"
	}

	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(path); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", path, err)
		}
		refreshRepoIndex(manager)
		return "depot " + name + " retire", nil
	}

	url := strings.TrimSpace(m.Param("url"))
	if url == "" {
		return "", fmt.Errorf("URL de depot manquante")
	}
	gpgKey := strings.TrimSpace(m.Param("gpg_key_path"))

	// La clé de signature est un fichier déposé par la phase précédente. Vérifier
	// sa présence ici plutôt que de laisser le gestionnaire de paquets échouer
	// plus tard : l'erreur pointe alors le vrai problème — un module de fichier
	// manquant dans la politique — au lieu d'un dépôt injoignable.
	if gpgKey != "" {
		if _, err := os.Stat(gpgKey); err != nil {
			return "", fmt.Errorf(
				"cle de signature %s absente : le module de fichier qui la depose manque dans la politique, ou son chemin differe", gpgKey)
		}
	}

	var content string
	if apt {
		signed := ""
		if gpgKey != "" {
			signed = "[signed-by=" + gpgKey + "] "
		}
		suite := strings.TrimSpace(m.Param("suite"))
		if suite == "" {
			suite = "stable main"
		}
		content = "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
			"deb " + signed + url + " " + suite + "\n"
	} else {
		enabled := "1"
		if m.Param("enabled") == "false" {
			enabled = "0"
		}
		gpgcheck := "0"
		gpgline := ""
		if gpgKey != "" {
			gpgcheck = "1"
			gpgline = "gpgkey=file://" + gpgKey + "\n"
		}
		content = "# Genere par Vaultaire (GPO). Ne pas editer a la main.\n" +
			"[vaultaire-" + name + "]\n" +
			"name=Vaultaire " + name + "\n" +
			"baseurl=" + url + "\n" +
			"enabled=" + enabled + "\n" +
			"gpgcheck=" + gpgcheck + "\n" + gpgline
	}

	if apt && m.Param("enabled") == "false" {
		// apt n'a pas de drapeau « désactivé » : un dépôt inactif est un dépôt
		// absent du répertoire. Le commenter laisserait un fichier trompeur.
		if _, err := removeSystemFile(path); err != nil {
			return "", fmt.Errorf("desactivation de %s impossible : %v", path, err)
		}
		refreshRepoIndex(manager)
		return "depot " + name + " desactive", nil
	}

	if err := writeSystemFile(path, content, 0o644); err != nil {
		return "", err
	}
	refreshRepoIndex(manager)
	return "depot " + name + " declare (" + url + ")", nil
}

// refreshRepoIndex rafraîchit l'index des paquets.
//
// L'échec n'est pas remonté comme une erreur du module : un dépôt injoignable au
// moment du rafraîchissement — coupure réseau, miroir en maintenance — ne rend
// pas la déclaration du dépôt fausse. C'est l'installation du paquet, à la phase
// suivante, qui échouera avec un message pertinent si le dépôt est réellement
// inutilisable.
func refreshRepoIndex(manager string) {
	switch manager {
	case "apt-get":
		_, _ = runCommandTimeout(RepoRefreshTimeout, "apt-get", "update")
	case "dnf", "yum":
		_, _ = runCommandTimeout(RepoRefreshTimeout, manager, "-q", "makecache")
	case "zypper":
		_, _ = runCommandTimeout(RepoRefreshTimeout, "zypper", "--non-interactive", "refresh")
	}
}
