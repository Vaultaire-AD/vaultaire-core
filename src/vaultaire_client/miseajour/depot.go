// Package miseajour porte ce que l'agent sait de sa mise à jour — pour
// l'instant, OÙ la trouver (TO-DO 114).
//
// # Le dépôt : un Nexus, en lecture anonyme
//
// Les paquets d'agent sont des releases dans un dépôt Nexus de type
// « vaultaire » (`public: true`, comme le dépôt `releases` de la configuration
// d'exemple). L'agent les lit SANS COMPTE : l'intégrité vient de la signature
// (pkg_signing, TO-DO 113), pas du contrôle d'accès — et cela évite de
// distribuer un jeton Nexus à chaque machine du parc.
//
//	<base>/repo/vaultaire/<dépôt>/download/v<version>/<archive>
//	<base>/repo/vaultaire/<dépôt>/download/v<version>/<archive>.<famille>.manifest
//	<base>/repo/vaultaire/<dépôt>/download/v<version>/<archive>.<famille>.manifest.sig
//
// # Où est Nexus : demandé au cluster
//
// L'agent n'a pas d'URL Nexus en configuration. Il la demande au core par la
// 04_15 — celle que le proxy emploie pour son relais HTTPS —, au moment où il
// en a besoin, et le core ne lui répond que pour les Nexus. Repli : l'URL de
// `update_repository` dans client_conf.json, si le cluster n'en annonce
// aucun.
//
// Le basculement (point 116) s'en sert, sur l'ordre de mise à jour (point
// 115), qui nomme la version et le dépôt.
package miseajour

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TypeNexus est le type de service des dépôts — clienttype.Nexus côté core.
const TypeNexus = "vaultaire_nexus"

// DepotParDefaut est le nom du dépôt de releases quand l'ordre n'en nomme
// pas : celui de la configuration d'exemple de Nexus.
const DepotParDefaut = "releases"

// DelaiDecouverte borne l'attente de la réponse du core.
const DelaiDecouverte = 10 * time.Second

// Source dit d'où vient une base de dépôt.
type Source string

const (
	SourceCluster Source = "cluster"
	SourceRepli   Source = "client_conf.json"
)

// Base est une URL de base Nexus, « https://hôte:port », sans chemin.
type Base struct {
	URL    string
	Source Source
}

// Bases rend les dépôts à essayer, dans l'ordre.
//
// annoncees : les « hôte:port » de la 04_16, dans l'ordre du core — priorité
// explicite, puis nom : un agent tente toujours les dépôts dans le même ordre,
// et ne se promène pas entre deux Nexus pas encore synchronisés. repli : la
// valeur de update_repository.
//
// Le repli ne sert QUE si le cluster n'annonce rien : un miroir local posé à
// la main ne doit pas passer devant les dépôts que l'exploitant a enrôlés.
//
// Le schéma est HTTPS : un Nexus n'annonce que son hôte et son port, et le
// registre Docker qu'il sert exige TLS. Le repli aussi : http:// est refusé
// depuis le 116. La signature juge les octets quel que soit le transport, mais
// un transport en clair laisse un tiers retenir une version (rejouer un vieux
// manifeste signé) ou observer le parc ; une AC privée se déclare dans
// update_tls_ca, la vérification ne se coupe pas.
func Bases(annoncees []string, repli string) ([]Base, error) {
	var out []Base
	for _, a := range annoncees {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		out = append(out, Base{URL: "https://" + a, Source: SourceCluster})
	}
	if len(out) > 0 {
		return out, nil
	}
	if strings.TrimSpace(repli) == "" {
		return nil, fmt.Errorf("aucun dépôt de mise à jour : le cluster n'annonce aucun Nexus, " +
			"et update_repository est vide dans client_conf.json")
	}
	b, err := NormaliserBase(repli)
	if err != nil {
		return nil, fmt.Errorf("update_repository : %w", err)
	}
	return []Base{{URL: b, Source: SourceRepli}}, nil
}

// NormaliserBase valide une URL de base : https, un hôte, rien après — ni
// chemin, ni requête, ni identifiants. Un chemin y ferait tout composer de
// travers ; des identifiants n'ont rien à y faire, le dépôt se lit sans compte.
func NormaliserBase(brute string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(brute))
	if err != nil {
		return "", fmt.Errorf("URL illisible : %w", err)
	}
	switch {
	case u.Scheme == "http":
		return "", fmt.Errorf("http:// refusé : le dépôt se lit en https:// (une AC privée se déclare dans update_tls_ca)")
	case u.Scheme != "https":
		return "", fmt.Errorf("schéma %q : https:// attendu", u.Scheme)
	case u.Host == "" || u.Hostname() == "":
		return "", fmt.Errorf("URL sans hôte")
	case u.User != nil:
		return "", fmt.Errorf("identifiants dans l'URL : le dépôt se lit sans compte")
	case strings.Trim(u.Path, "/") != "" || u.RawQuery != "" || u.Fragment != "":
		return "", fmt.Errorf("URL de base attendue, sans chemin (%q)", u.Path)
	}
	return u.Scheme + "://" + u.Host, nil
}

// URLFichier compose l'adresse d'un fichier d'une release.
func URLFichier(base, depot, version, fichier string) string {
	if strings.TrimSpace(depot) == "" {
		depot = DepotParDefaut
	}
	return strings.TrimRight(base, "/") + "/repo/vaultaire/" + url.PathEscape(depot) +
		"/download/v" + url.PathEscape(strings.TrimPrefix(version, "v")) + "/" + url.PathEscape(fichier)
}

// NomArchive rend le nom de l'archive d'agent d'une version — celui que
// release.yaml produit.
func NomArchive(version string) string {
	return "vaultaire_client-v" + strings.TrimPrefix(version, "v") + "-linux-amd64.tar.gz"
}

// NomManifeste et NomSignature : à côté de l'archive, un par famille.
func NomManifeste(version, famille string) string {
	return NomArchive(version) + "." + famille + ".manifest"
}

func NomSignature(version, famille string) string { return NomManifeste(version, famille) + ".sig" }
