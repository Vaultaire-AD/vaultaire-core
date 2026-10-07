// Package controle répond à une question, et une seule : cet agent peut-il
// démarrer ? — TO-DO 112.
//
// # Pourquoi cela existe
//
// Les trois piles PAM que pose `rocky.sh` meurent quand le module ne joint pas
// l'agent (`default=die`), sans repli vers `system-auth`. Un agent qui ne
// démarre pas rend donc la machine inaccessible à TOUS les comptes du domaine,
// sur console, SSH et GDM à la fois.
//
// Or rien ne disait, avant de lancer le service, s'il allait tenir : un fichier
// de configuration tronqué ou une clé privée absente se découvraient en
// regardant le service mourir en boucle. `vaultaire_client --check` le dit
// d'avance, en une commande, et systemd la joue avant chaque démarrage
// (`ExecStartPre`) : un agent qui ne peut pas démarrer est alors un service EN
// ÉCHEC, nommé et motivé, au lieu d'une boucle de relances.
//
// # Ce que le contrôle ne fait PAS
//
// Il n'ouvre ni socket ni tunnel, n'écrit rien, ne modifie aucun état : il lit.
// On peut le lancer sur une machine en service, à côté de l'agent qui tourne.
//
// # Bloquant, ou seulement signalé
//
// La règle : n'est BLOQUANT que ce qui empêche déjà l'agent de servir une seule
// authentification — configuration illisible, identité absente, clé privée
// inutilisable. Tout ce que l'agent tolère aujourd'hui en le journalisant (une
// clé du core à redemander, une empreinte absente) reste une ATTENTION.
//
// Elle n'est pas négociable : ce contrôle garde la porte du service. S'il
// refusait un état dans lequel l'agent fonctionne, c'est lui qui couperait la
// machine — exactement ce qu'il est là pour éviter.
package controle

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"duckynetworkclient/V1/duckynetwork/serveurauth"
	"duckynetworkclient/V1/duckynetwork/storage"
	"vaultaire_client/config"

	"gopkg.in/yaml.v3"
)

// Gravite classe un constat.
type Gravite int

const (
	// Bon : conforme.
	Bon Gravite = iota
	// Attention : l'agent démarre et travaille, mais quelque chose mérite un
	// regard.
	Attention
	// Bloquant : l'agent ne pourra servir aucune authentification.
	Bloquant
)

func (g Gravite) String() string {
	switch g {
	case Bon:
		return "OK"
	case Attention:
		return "ATTENTION"
	default:
		return "BLOQUANT"
	}
}

// Constat est le résultat d'une vérification.
type Constat struct {
	Sujet   string
	Gravite Gravite
	Detail  string
}

// Chemins désigne ce que le contrôle lit. Un champ par fichier, pour qu'un test
// le dirige vers un dossier à lui.
type Chemins struct {
	Configuration string
	Identite      string
	ClePrivee     string
	CleDuCore     string
	Empreinte     string
	Journaux      string
}

// CheminConfiguration est le fichier de configuration de l'agent.
const CheminConfiguration = "/etc/vaultaire_client/client_conf.json"

// CheminsReels rend les emplacements que l'agent emploie réellement — résolus
// par les mêmes fonctions que lui, variables d'environnement comprises. Un
// contrôle qui regarderait ailleurs que l'agent ne contrôlerait rien.
func CheminsReels() Chemins {
	return Chemins{
		Configuration: CheminConfiguration,
		Identite:      storage.SoftwarePathResolu(),
		ClePrivee:     storage.CheminDansKeyPath("private_key.pem"),
		CleDuCore:     storage.CheminDansKeyPath("serveurpublickey.pem"),
		Empreinte:     serveurauth.CoreFingerprintPath(),
		Journaux:      storage.LogPathResolu(),
	}
}

// Verifier joue tous les contrôles et rend leurs constats, dans l'ordre où un
// exploitant les lirait : ce dont dépend tout le reste d'abord.
func Verifier(c Chemins) []Constat {
	return []Constat{
		verifierConfiguration(c.Configuration),
		verifierIdentite(c.Identite),
		verifierClePrivee(c.ClePrivee),
		verifierCleDuCore(c.CleDuCore, c.Empreinte),
		verifierJournaux(c.Journaux),
	}
}

// Bloquants compte ce qui empêche de démarrer.
func Bloquants(constats []Constat) int {
	n := 0
	for _, c := range constats {
		if c.Gravite == Bloquant {
			n++
		}
	}
	return n
}

// Rapport écrit les constats, un par ligne, puis la conclusion. Rend le nombre
// de constats bloquants : c'est le code de sortie de `--check`.
func Rapport(w io.Writer, entete string, constats []Constat) int {
	fmt.Fprintln(w, entete)
	for _, c := range constats {
		fmt.Fprintf(w, "  [%-9s] %-14s %s\n", c.Gravite, c.Sujet, c.Detail)
	}
	bloquants := Bloquants(constats)
	if bloquants == 0 {
		fmt.Fprintln(w, "Résultat : l'agent peut démarrer.")
	} else {
		fmt.Fprintf(w, "Résultat : l'agent ne peut PAS démarrer — %d point(s) bloquant(s). "+
			"Tant qu'il est arrêté, aucun compte du domaine n'ouvre de session sur cette machine ; "+
			"root et les comptes locaux passent toujours.\n", bloquants)
	}
	return bloquants
}

func lisible(chemin string, err error) string {
	switch {
	case os.IsNotExist(err):
		return chemin + " est absent"
	case os.IsPermission(err):
		return chemin + " n'est pas lisible par cet utilisateur (le contrôle se lance en root, comme l'agent)"
	default:
		return chemin + " : " + err.Error()
	}
}

// verifierConfiguration : le fichier se lit, comme l'agent le lit, et désigne
// au moins un nœud.
func verifierConfiguration(chemin string) Constat {
	const sujet = "configuration"
	c, err := config.Lire(chemin)
	if err != nil {
		if os.IsNotExist(err) || os.IsPermission(err) {
			return Constat{sujet, Bloquant, lisible(chemin, err)}
		}
		return Constat{sujet, Bloquant, err.Error()}
	}
	utilisables := 0
	for _, s := range append(append([]config.ServerConfig{}, c.Servers...), c.Learned...) {
		if strings.TrimSpace(s.IP) != "" && s.Port > 0 && s.Port <= 65535 {
			utilisables++
		}
	}
	if utilisables == 0 {
		return Constat{sujet, Bloquant, chemin + " ne désigne aucun core utilisable " +
			"(« servers » : une adresse et un port entre 1 et 65535)"}
	}
	return Constat{sujet, Bon, fmt.Sprintf("%s — %d core(s) d'installation, %d appris",
		chemin, len(c.Servers), len(c.Learned))}
}

// verifierIdentite : la machine sait qui elle est.
//
// L'agent d'aujourd'hui démarre sans identité, en l'écrivant au journal — mais
// il ne peut alors ouvrir AUCUNE session : c'est bien un état où il ne sert
// aucune authentification.
func verifierIdentite(chemin string) Constat {
	const sujet = "identité"
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return Constat{sujet, Bloquant, lisible(chemin, err)}
	}
	var id storage.ClientSoftware
	if err := yaml.Unmarshal(brut, &id); err != nil {
		return Constat{sujet, Bloquant, chemin + " illisible : " + err.Error()}
	}
	if strings.TrimSpace(id.NewClient.Computeur_id) == "" {
		return Constat{sujet, Bloquant, chemin + " ne porte pas d'identifiant de machine (client_software.computeur_id)"}
	}
	return Constat{sujet, Bon, "machine " + id.NewClient.Computeur_id}
}

// verifierClePrivee : la clé se décode EXACTEMENT comme à l'usage.
//
// Le socle la lit en PKCS#1 et rien d'autre (DecodeWithClientPrivateKey). Un
// contrôle plus tolérant — qui accepterait du PKCS#8 — annoncerait prêt un
// agent incapable de déchiffrer la première réponse du core.
func verifierClePrivee(chemin string) Constat {
	const sujet = "clé privée"
	brut, err := os.ReadFile(chemin)
	if err != nil {
		return Constat{sujet, Bloquant, lisible(chemin, err)}
	}
	bloc, _ := pem.Decode(brut)
	if bloc == nil {
		return Constat{sujet, Bloquant, chemin + " n'est pas du PEM (fichier tronqué ou vide ?)"}
	}
	cle, err := x509.ParsePKCS1PrivateKey(bloc.Bytes)
	if err != nil {
		return Constat{sujet, Bloquant, chemin + " ne se décode pas en clé RSA PKCS#1 : " + err.Error()}
	}
	if err := cle.Validate(); err != nil {
		return Constat{sujet, Bloquant, chemin + " : clé incohérente : " + err.Error()}
	}
	detail := fmt.Sprintf("RSA %d bits", cle.N.BitLen())
	if info, err := os.Stat(chemin); err == nil && info.Mode().Perm()&0o077 != 0 {
		return Constat{sujet, Attention, fmt.Sprintf(
			"%s, mais lisible au-delà de son propriétaire (mode %04o) : chmod 400 %s",
			detail, info.Mode().Perm(), chemin)}
	}
	return Constat{sujet, Bon, detail}
}

// verifierCleDuCore : jamais bloquant.
//
// Absente, l'agent la redemande au premier contact. Illisible, il l'écarte et
// la redemande s'il a une empreinte pour vérifier la remplaçante. C'est lui qui
// tranche, pas ce contrôle.
func verifierCleDuCore(cheminCle, cheminEmpreinte string) Constat {
	const sujet = "clé du core"
	empreintes := 0
	if brut, err := os.ReadFile(cheminEmpreinte); err == nil {
		for _, ligne := range strings.Split(string(brut), "\n") {
			if strings.HasPrefix(strings.TrimSpace(ligne), "SHA256:") {
				empreintes++
			}
		}
	}
	brut, err := os.ReadFile(cheminCle)
	switch {
	case os.IsNotExist(err) && empreintes > 0:
		return Constat{sujet, Bon, fmt.Sprintf(
			"absente — elle sera demandée au core et vérifiée contre %d empreinte(s)", empreintes)}
	case os.IsNotExist(err):
		return Constat{sujet, Attention, "absente et aucune empreinte déposée : " +
			"la première clé reçue sera acceptée en confiance"}
	case err != nil:
		return Constat{sujet, Attention, lisible(cheminCle, err)}
	}
	if _, err := serveurauth.EmpreinteClePublique(string(brut)); err != nil {
		if empreintes > 0 {
			return Constat{sujet, Attention, cheminCle + " illisible — l'agent l'écartera et la redemandera"}
		}
		return Constat{sujet, Attention, cheminCle + " illisible et aucune empreinte pour vérifier une remplaçante : " +
			"supprimer ce fichier, ou réinstaller l'agent avec « vlt create -join »"}
	}
	if empreintes == 0 {
		return Constat{sujet, Attention, "présente, sans empreinte déposée pour l'attester (confiance au premier usage)"}
	}
	return Constat{sujet, Bon, fmt.Sprintf("présente, %d empreinte(s) déposée(s)", empreintes)}
}

// verifierJournaux : sans journal l'agent travaille, mais on ne saura rien de
// ce qu'il fait — jamais bloquant.
func verifierJournaux(repertoire string) Constat {
	const sujet = "journaux"
	propre := filepath.Clean(repertoire)
	info, err := os.Stat(propre)
	switch {
	case os.IsNotExist(err):
		return Constat{sujet, Attention, propre + " n'existe pas encore (l'agent le crée à sa première ligne)"}
	case err != nil:
		return Constat{sujet, Attention, lisible(propre, err)}
	case !info.IsDir():
		return Constat{sujet, Attention, propre + " n'est pas un répertoire : l'agent n'écrira aucun journal"}
	}
	return Constat{sujet, Bon, propre}
}
