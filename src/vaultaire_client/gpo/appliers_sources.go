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

// magasinCA décrit le magasin de confiance d'une famille de distribution.
type magasinCA struct {
	famille string
	dir     string
	suffix  string
	refresh []string
}

// caStorePaths liste les magasins de confiance connus, avec la commande de
// régénération associée.
var caStorePaths = []magasinCA{
	{"Debian/Ubuntu", "/usr/local/share/ca-certificates", ".crt", []string{"update-ca-certificates"}},
	{"RHEL/Rocky", "/etc/pki/ca-trust/source/anchors", ".pem", []string{"update-ca-trust", "extract"}},
}

// applyTrustedCA installe ou retire une CA du magasin de confiance système.
func applyTrustedCA(ctx Context, m Module) (string, error) {
	name := strings.TrimSpace(m.Param("name"))
	if name == "" {
		return "", fmt.Errorf("nom de CA manquant")
	}

	store, ok := detectCAStore()
	if !ok {
		return "", fmt.Errorf("aucun magasin de confiance utilisable : cherche %s", famillesConnues())
	}
	path := store.dir + "/vaultaire-" + name + store.suffix

	if m.Param("state") == "absent" {
		if _, err := removeSystemFile(path); err != nil {
			return "", fmt.Errorf("retrait de %s impossible : %v", path, err)
		}
		if _, err := runCommand(store.refresh[0], store.refresh[1:]...); err != nil {
			return "", err
		}
		recordCheck(CheckCADansMagasin, name, "absent")
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

	// L'attente porte sur le magasin COMPILÉ, pas sur le fichier déposé — que le
	// scan des fichiers surveille déjà.
	//
	// Ce qui lui échappe : une CA mise en liste noire, ou retirée de
	// /etc/ca-certificates.conf sur Debian. Dans les deux cas la source est
	// intacte et plus aucune connexion TLS ne fait confiance à cette autorité.
	//
	// L'empreinte porte sur le DER : update-ca-trust réécrit les certificats
	// qu'il agrège — longueur de ligne, ordre, en-têtes — et chercher le texte
	// déposé échouerait sur une machine parfaitement conforme.
	if empreinte := EmpreintePEM(cert); empreinte != "" {
		recordCheck(CheckCADansMagasin, name, empreinte)
	}
	return "CA " + name + " installee (" + store.dir + ")", nil
}

// detectCAStore retourne le magasin de confiance utilisable sur la machine.
//
// # Ce que la version précédente reconnaissait, et le défaut que ça donnait
//
// Elle retenait le PREMIER RÉPERTOIRE qui existe, Debian en tête de liste. Or
// `/usr/local/share/ca-certificates` est un répertoire ordinaire sous
// `/usr/local` : il peut parfaitement exister, vide, sur une Rocky. Une Rocky
// était alors prise pour une Debian, et l'agent lançait
// `update-ca-certificates`, qui n'y existe pas. Le module échouait, et le
// message ne disait pas pourquoi — il a fallu une session de recette pour le
// comprendre.
//
// # Ce qui identifie réellement une famille
//
// La COMMANDE de régénération, pas le répertoire. Un magasin n'est utilisable
// que si le programme qui le compile est là : c'est lui qui rend la CA
// effective, déposer le fichier ne suffit pas. Un répertoire, lui, ne prouve
// rien — n'importe quel paquet, ou un administrateur, a pu le créer.
//
// Le répertoire garde un rôle : départager deux familles dont les deux
// commandes seraient présentes, ce qui arrive sur une machine où l'on a
// installé les outils de l'autre distribution.
func detectCAStore() (magasinCA, bool) {
	var premierPossible magasinCA
	trouve := false

	for _, store := range caStorePaths {
		if !commandExists(store.refresh[0]) {
			continue
		}
		// La commande est là : cette famille est possible. Si son répertoire
		// existe aussi, c'est elle, sans hésitation.
		if info, err := os.Stat(store.dir); err == nil && info.IsDir() {
			return store, true
		}
		if !trouve {
			premierPossible, trouve = store, true
		}
	}

	// Commande présente mais répertoire absent : le répertoire d'ancrage est
	// créé. C'est un emplacement documenté de la distribution, pas un chemin
	// inventé, et le refuser bloquerait le module sur une machine parfaitement
	// capable de faire ce qu'on lui demande.
	if trouve {
		if err := os.MkdirAll(premierPossible.dir, 0o755); err == nil {
			return premierPossible, true
		}
	}
	return magasinCA{}, false
}

// famillesConnues rend la liste des magasins cherchés, pour le message d'échec.
//
// Un « aucun magasin reconnu » qui ne dit pas ce qui a été cherché oblige à
// aller lire le code — c'est précisément ce qui a coûté du temps ici.
func famillesConnues() string {
	var parts []string
	for _, store := range caStorePaths {
		parts = append(parts, store.famille+" ("+store.refresh[0]+")")
	}
	return strings.Join(parts, ", ")
}

// ---------------------------------------------------------------------------
// Résolution DNS
// ---------------------------------------------------------------------------

// Le module dns_resolver vit dans appliers_dns.go.

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
