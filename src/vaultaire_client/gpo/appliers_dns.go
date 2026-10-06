package gpo

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Résolution DNS — module dns_resolver
// ---------------------------------------------------------------------------
//
// # Pourquoi trois façons d'appliquer
//
// Le module ne connaissait que systemd-resolved : il écrivait un fichier sous
// resolved.conf.d/ puis lançait `systemctl restart systemd-resolved`. C'est la
// bonne méthode sur Debian ou Ubuntu, où resolved tient la résolution.
//
// Sur Rocky / RHEL 9, resolved n'est PAS actif : NetworkManager écrit lui-même
// /etc/resolv.conf. Le redémarrage échouait (« Unit systemd-resolved.service
// not found » sur une image minimale), ou démarrait un résolveur que personne
// n'interrogeait — la politique se disait appliquée sans rien changer. Et le
// vérificateur, qui lit `resolvectl`, échouait à son tour.
//
// Le module détecte donc QUI tient la résolution, et applique chez lui :
//
//	resolved        systemd-resolved actif           drop-in resolved.conf.d/
//	networkmanager  NetworkManager actif, sans resolved   [global-dns] dans conf.d/
//	resolvconf      ni l'un ni l'autre               /etc/resolv.conf écrit
//
// L'ordre compte : sur Ubuntu Desktop, NetworkManager ET resolved tournent, et
// NetworkManager y délègue à resolved — c'est donc resolved qu'on règle.
//
// # Ce qui ne change pas
//
// Aucun service n'est jamais REDÉMARRÉ s'il n'était pas actif : démarrer un
// résolveur par effet de bord peut prendre le port 53 à un autre. Et tout échec
// de rechargement restaure la configuration précédente : une résolution cassée
// coupe la machine du core lui-même, et plus aucune politique corrective ne
// l'atteindrait.

// Fichiers. Des variables et non des constantes : les tests les déplacent dans
// un répertoire temporaire.
var (
	resolvedDropIn = "/etc/systemd/resolved.conf.d/99-vaultaire-gpo.conf"
	nmDropIn       = "/etc/NetworkManager/conf.d/99-vaultaire-gpo.conf"
	resolvConf     = "/etc/resolv.conf"

	// resolvConfAvant garde le resolv.conf d'origine, pour le rendre quand la
	// politique est retirée (state=absent).
	resolvConfAvant = StateDir + "/resolv.conf.avant-gpo"
)

// Identifiants de moteur. Pour resolved, l'attente enregistrée garde la cible
// « global » des versions précédentes : la renommer ferait voir une dérive sur
// toutes les machines déjà conformes.
const (
	moteurResolved       = "resolved"
	moteurNetworkManager = "networkmanager"
	moteurResolvConf     = "resolvconf"
)

// serviceActif dit si une unité systemd est active. Sans systemctl, rien ne
// l'est.
func serviceActif(unite string) bool {
	if !commandExists("systemctl") {
		return false
	}
	_, err := runCommand("systemctl", "is-active", "--quiet", unite)
	return err == nil
}

// detecterMoteurDNS désigne ce qui tient la résolution sur cette machine.
var detecterMoteurDNS = func() string {
	if serviceActif("systemd-resolved") {
		return moteurResolved
	}
	if serviceActif("NetworkManager") {
		return moteurNetworkManager
	}
	return moteurResolvConf
}

// applyDNSResolver fixe les serveurs DNS et le domaine de recherche.
func applyDNSResolver(ctx Context, m Module) (string, error) {
	moteur := detecterMoteurDNS()

	if m.Param("state") == "absent" {
		return retirerDNS(moteur)
	}

	servers := normalizeList(m.Param("servers"))
	if servers == "" {
		return "", fmt.Errorf("aucun serveur DNS fourni")
	}
	domains := normalizeList(m.Param("search_domain"))

	switch moteur {
	case moteurResolved:
		return appliquerDNSResolved(servers, domains)
	case moteurNetworkManager:
		return appliquerDNSNetworkManager(servers, domains)
	default:
		return appliquerDNSResolvConf(servers, domains)
	}
}

// --- systemd-resolved --------------------------------------------------------

func appliquerDNSResolved(servers, domains string) (string, error) {
	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	b.WriteString("[Resolve]\n")
	b.WriteString("DNS=" + servers + "\n")
	if domains != "" {
		b.WriteString("Domains=" + domains + "\n")
	}

	previous, had := readFileIfExists(resolvedDropIn)
	if err := writeSystemFile(resolvedDropIn, b.String(), 0o644); err != nil {
		return "", err
	}
	if _, err := runCommand("systemctl", "restart", "systemd-resolved"); err != nil {
		restoreOrRemove(resolvedDropIn, previous, had)
		_, _ = runCommand("systemctl", "restart", "systemd-resolved")
		return "", fmt.Errorf("redemarrage de systemd-resolved impossible, configuration restauree : %v", err)
	}

	// L'attente porte sur les serveurs GLOBAUX réellement chargés par resolved.
	// Un DNS posé sur une INTERFACE — par DHCP — prime sur le global pour les
	// requêtes de cette interface : ce n'est pas une dérive de ce module.
	recordCheck(CheckDNSServers, "global", servers)
	return "DNS (systemd-resolved) = " + servers, nil
}

// --- NetworkManager ---------------------------------------------------------

// contenuNetworkManager rend la configuration DNS globale de NetworkManager.
//
// [global-dns] remplace le DNS de TOUTES les connexions, DHCP compris : c'est
// l'équivalent du « global » de resolved, et le seul réglage qui survive au
// renouvellement d'un bail. NetworkManager réécrit alors lui-même
// /etc/resolv.conf avec ces serveurs.
func contenuNetworkManager(servers, domains string) string {
	virgules := func(l string) string { return strings.Join(strings.Fields(l), ",") }
	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	b.WriteString("[global-dns]\n")
	if domains != "" {
		b.WriteString("searches=" + virgules(domains) + "\n")
	}
	b.WriteString("\n[global-dns-domain-*]\n")
	b.WriteString("servers=" + virgules(servers) + "\n")
	return b.String()
}

// rechargerNetworkManager relit la configuration sans couper les connexions.
//
// `nmcli general reload` sans option (NetworkManager ≥ 1.22, donc RHEL/Rocky
// 9) équivaut à un SIGHUP : conf.d/ relu, DNS global réappliqué, resolv.conf
// réécrit. `systemctl reload` fait de même sur les versions plus anciennes.
// Jamais `restart` : il couperait les interfaces.
func rechargerNetworkManager() error {
	if commandExists("nmcli") {
		if _, err := runCommand("nmcli", "general", "reload"); err == nil {
			return nil
		}
	}
	_, err := runCommand("systemctl", "reload", "NetworkManager")
	return err
}

func appliquerDNSNetworkManager(servers, domains string) (string, error) {
	previous, had := readFileIfExists(nmDropIn)
	if err := writeSystemFile(nmDropIn, contenuNetworkManager(servers, domains), 0o644); err != nil {
		return "", err
	}
	if err := rechargerNetworkManager(); err != nil {
		restoreOrRemove(nmDropIn, previous, had)
		_ = rechargerNetworkManager()
		return "", fmt.Errorf("rechargement de NetworkManager impossible, configuration restauree : %v", err)
	}
	recordCheck(CheckDNSServers, moteurNetworkManager, servers)
	return "DNS (NetworkManager) = " + servers, nil
}

// --- resolv.conf seul ---------------------------------------------------------

func contenuResolvConf(servers, domains string) string {
	var b strings.Builder
	b.WriteString("# Genere par Vaultaire (GPO). Ne pas editer a la main.\n")
	if domains != "" {
		b.WriteString("search " + domains + "\n")
	}
	for _, s := range strings.Fields(servers) {
		b.WriteString("nameserver " + s + "\n")
	}
	return b.String()
}

func appliquerDNSResolvConf(servers, domains string) (string, error) {
	// Le fichier d'origine est gardé UNE fois : réappliquer la politique ne
	// doit pas remplacer la sauvegarde par la version de la politique.
	if _, deja := readFileIfExists(resolvConfAvant); !deja {
		if avant, ok := readFileIfExists(resolvConf); ok {
			if err := writeFileQuiet(resolvConfAvant, avant); err != nil {
				return "", fmt.Errorf("sauvegarde de %s impossible : %v", resolvConf, err)
			}
		}
	}
	if err := writeSystemFile(resolvConf, contenuResolvConf(servers, domains), 0o644); err != nil {
		return "", err
	}
	recordCheck(CheckDNSServers, moteurResolvConf, servers)
	return "DNS (/etc/resolv.conf) = " + servers, nil
}

// --- retrait ------------------------------------------------------------------

// retirerDNS rend la résolution à la configuration locale, quel que soit le
// moteur qui l'avait reçue : une machine a pu changer de moteur entre
// l'application et le retrait.
func retirerDNS(moteur string) (string, error) {
	if _, err := removeSystemFile(resolvedDropIn); err != nil {
		return "", fmt.Errorf("retrait de %s impossible : %v", resolvedDropIn, err)
	}
	if _, err := removeSystemFile(nmDropIn); err != nil {
		return "", fmt.Errorf("retrait de %s impossible : %v", nmDropIn, err)
	}
	if avant, ok := readFileIfExists(resolvConfAvant); ok {
		if err := writeSystemFile(resolvConf, avant, 0o644); err != nil {
			return "", fmt.Errorf("restauration de %s impossible : %v", resolvConf, err)
		}
		_ = removeQuiet(resolvConfAvant)
	}

	// Seuls les services ACTIFS sont rechargés : jamais de démarrage par effet
	// de bord.
	switch moteur {
	case moteurResolved:
		_, _ = runCommand("systemctl", "restart", "systemd-resolved")
	case moteurNetworkManager:
		_ = rechargerNetworkManager()
	}
	return "resolution DNS rendue a la configuration locale", nil
}

// writeFileQuiet écrit un fichier d'ÉTAT de l'agent (sauvegarde), hors de
// l'inventaire des fichiers de politique : il n'est pas une configuration de la
// machine, et le surveiller ferait signaler une dérive quand on le retire.
func writeFileQuiet(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// removeQuiet retire un fichier d'état, hors inventaire.
func removeQuiet(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
