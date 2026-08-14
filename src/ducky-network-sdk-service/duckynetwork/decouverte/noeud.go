package decouverte

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/serveurauth"
)

// L'enregistrement d'un nœud dans le cluster (04_01, 04_07, 04_05).
//
// # Ce que cela débloque
//
// Le proxy s'enrôlait, s'authentifiait, puis attendait un signal que personne
// n'envoyait. Les quatre trames dont il a besoin étaient ÉCRITES CÔTÉ SERVEUR
// depuis longtemps — 04_01, 04_03, 04_05, 04_07 — mais le catalogue de types ne
// les accordait à personne, et rien ne les émettait.
//
// Un proxy déployé n'apparaissait donc dans aucune liste, aucun agent n'y
// passait, et la table `proxy_metrics` n'avait jamais reçu une ligne.
//
// # Ce que ce fichier ne fait PAS
//
// Il ne relaie rien. L'enregistrement rend le proxy VISIBLE ; le relais TCP est
// un autre lot, et les séparer permet de vérifier le premier sans écrire une
// ligne de réseau neuve sur le chemin qui porte les mots de passe du parc.

// InfosNoeud décrit ce qu'un nœud déclare de lui-même.
type InfosNoeud struct {
	Hostname string
	FQDN     string
	IP       string
	Role     string
	Domaine  string
	Port     int
}

// DecrireNoeudLocal compose la déclaration de cette machine.
//
// # L'empreinte n'est PAS dans cette structure
//
// Elle est calculée au moment de l'émission, depuis la clé réellement présente
// sur le disque. La porter ici laisserait un appelant en fournir une autre —
// c'est-à-dire déclarer au cluster une empreinte que ce nœud ne sert pas, et
// tout agent qui l'apprendrait refuserait ensuite sa vraie clé.
func DecrireNoeudLocal(role, domaine string, port int) (InfosNoeud, error) {
	hostname, err := os.Hostname()
	if err != nil || strings.TrimSpace(hostname) == "" {
		return InfosNoeud{}, fmt.Errorf("nom d'hôte indisponible : %v", err)
	}
	ip := adressePrimaire()
	if ip == "" {
		return InfosNoeud{}, fmt.Errorf(
			"aucune adresse IP non locale trouvée : ce nœud ne serait joignable par personne")
	}
	if port < 1 || port > 65535 {
		return InfosNoeud{}, fmt.Errorf("port d'écoute invalide (%d)", port)
	}
	return InfosNoeud{
		Hostname: hostname,
		FQDN:     hostname,
		IP:       ip,
		Role:     role,
		Domaine:  domaine,
		Port:     port,
	}, nil
}

// ConstruireEnregistrement compose la trame 04_01.
//
//	hostname\nfqdn\nip\nrole\ndomaine\nport\nempreinte
//
// Le port et l'empreinte sont en QUEUE parce qu'ils sont venus après : un core
// resté à l'ancienne version lit les cinq premières lignes et ignore le reste,
// au lieu de lire le domaine comme un port.
func ConstruireEnregistrement(sessionKey, clientID string, n InfosNoeud) (string, error) {
	empreinte, err := empreinteLocale()
	if err != nil {
		// Refus plutôt qu'un enregistrement sans empreinte. Un nœud annoncé sans
		// de quoi le reconnaître serait écarté par le core de toute façon ; échouer
		// ici le dit au bon endroit, avec la vraie cause.
		return "", err
	}

	return strings.Join([]string{
		"04_01", "serveur_central", sessionKey, "vaultaire", clientID,
		n.Hostname, n.FQDN, n.IP, n.Role, n.Domaine,
		strconv.Itoa(n.Port), empreinte,
	}, "\n"), nil
}

// ConstruireBattement compose la trame 04_07.
func ConstruireBattement(sessionKey, clientID, hostname string) string {
	return strings.Join([]string{
		"04_07", "serveur_central", sessionKey, "vaultaire", clientID, hostname,
	}, "\n")
}

// ConstruireMetrique compose la trame 04_05.
//
//	hostname\nip\ntype\nvaleur\nextra_json
//
// La valeur est formatée sans notation exponentielle : le core la lit avec
// ParseFloat, qui l'accepterait, mais la table est aussi lue à l'œil et
// « 1.5e+03 » y est illisible.
func ConstruireMetrique(sessionKey, clientID string, n InfosNoeud, typeMetrique string, valeur float64) string {
	return strings.Join([]string{
		"04_05", "serveur_central", sessionKey, "vaultaire", clientID,
		n.Hostname, n.IP, typeMetrique,
		strconv.FormatFloat(valeur, 'f', -1, 64),
		"{}",
	}, "\n")
}

// DemarrerNoeud enregistre ce nœud puis entretient son battement.
//
// # Pourquoi le battement passe par une boucle propre et non par reglages.Boucle
//
// `reglages` vit côté core et lit la base. Un proxy n'a ni l'un ni l'autre : la
// cadence lui est donc locale, et volontairement PLUS COURTE que le seuil de
// péremption appliqué par le core — sinon un nœud parfaitement vivant serait
// déclaré hors ligne entre deux battements, et retiré de la liste servie aux
// agents au moment précis où il fonctionne.
func DemarrerNoeud(sessionKey func() string, n InfosNoeud, cadence time.Duration) {
	if cadence <= 0 {
		cadence = CadenceBattementParDefaut
	}

	go func() {
		defer logs.Recover("enregistrement du nœud")

		if !enregistrer(sessionKey, n) {
			// L'enregistrement a échoué : on ne bat pas dans le vide. Le
			// battement met à jour une ligne qui n'existe pas — le core répond
			// sans rien faire, et le journal se remplit d'accusés qui ne
			// signifient rien.
			logs.Write_log("ERROR",
				"nœud : enregistrement échoué, le battement n'est pas démarré")
			return
		}

		for range time.Tick(cadence) {
			cle := sessionKey()
			if strings.TrimSpace(cle) == "" {
				logs.Write_log("WARNING", "nœud : aucune session, battement non envoyé")
				continue
			}
			if envoyer == nil {
				return
			}
			envoyer(ConstruireBattement(cle, clientID, n.Hostname))
		}
	}()

	logs.Write_log("INFO", fmt.Sprintf(
		"nœud : %s (%s, %s:%d) enregistré, battement toutes les %s",
		n.Hostname, n.Role, n.IP, n.Port, cadence))
}

// CadenceBattementParDefaut doit rester NETTEMENT sous le seuil de péremption
// appliqué par le core, sinon un nœud vivant est déclaré hors ligne entre deux
// battements.
const CadenceBattementParDefaut = 20 * time.Second

func enregistrer(sessionKey func() string, n InfosNoeud) bool {
	if envoyer == nil {
		logs.Write_log("ERROR", "nœud : aucun émetteur branché")
		return false
	}
	cle := sessionKey()
	if strings.TrimSpace(cle) == "" {
		logs.Write_log("ERROR", "nœud : aucune session établie")
		return false
	}
	trame, err := ConstruireEnregistrement(cle, clientID, n)
	if err != nil {
		logs.Write_log("ERROR", "nœud : "+err.Error())
		return false
	}
	envoyer(trame)
	return true
}

// empreinteLocale rend l'empreinte de la clé publique de CE nœud.
//
// Elle est lue depuis la clé sur le disque — la même que celle servie aux
// clients qui joindront ce nœud. Toute autre source rendrait possible qu'elles
// divergent, et un agent qui aurait appris l'empreinte déclarée refuserait
// ensuite la vraie clé.
func empreinteLocale() (string, error) {
	pem := serveurauth.GetPublicKey()
	if strings.TrimSpace(pem) == "" || pem == "err" {
		return "", fmt.Errorf(
			"clé publique locale introuvable : ce nœud ne peut pas s'annoncer, " +
				"les agents n'auraient pas de quoi reconnaître sa clé")
	}
	return serveurauth.EmpreinteClePublique(pem)
}

// adressePrimaire cherche une adresse IPv4 non locale.
//
// Reprend la logique du core, volontairement : les deux répondent à la même
// question et doivent répondre pareil. Un nœud qui se déclarerait sur 127.0.0.1
// serait annoncé au parc comme joignable et ne le serait par personne.
func adressePrimaire() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		adresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range adresses {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}
