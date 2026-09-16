// Package enrollment enrôle un client service auprès du core — trames 01_05 à
// 01_09.
//
// # Le flux
//
//	01_05  →  clé d'enrôlement + clé de session TEMPORAIRE   (RSA, clé du core)
//	01_06  ←  identifiant attribué + type de client          (AES, clé temporaire)
//	01_07  →  clé publique du service                        (AES, clé temporaire)
//	01_08  ←  confirmation                                   (RSA, clé du service)
//	01_09  ←  refus, EN CLAIR
//
// # Pourquoi une clé temporaire
//
// Une clé publique RSA-4096 pèse environ 800 octets en PEM. Une charge RSA-OAEP
// sur clé 4096 en accepte 446. Elle ne peut donc PAS voyager dans une enveloppe
// asymétrique, et aucun encodage n'y change rien : le problème est que la charge
// utile d'une enveloppe RSA est plus petite que la clé qu'on veut y mettre.
//
// La clé temporaire, elle, tient sans peine en RSA — 32 octets — et ouvre un
// canal symétrique qui n'a plus de limite de taille.
//
// # Ce que le service ne choisit pas
//
// Ni son identifiant, ni son type : les deux viennent du core. Le premier est
// attribué, le second est porté par la clé d'enrôlement. Un service qui pourrait
// annoncer son type n'aurait qu'à s'enrôler pour se donner les privilèges qu'il
// veut.
//
// # La connexion est jetable
//
// Elle sert à l'enrôlement et se ferme à la fin. Le service en ouvre une neuve
// pour la poignée de main 01_01, avec son identité cette fois.
package enrollment

import (
	"crypto/rand"
	"duckynetworkclient/V1/config"
	"duckynetworkclient/V1/duckynetwork/keymanagement"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/serveurauth"
	"duckynetworkclient/V1/duckynetwork/storage"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// tmpKeyBytes : AES-256, comme la clé de session ordinaire.
const tmpKeyBytes = 32

// dialTimeout borne l'établissement de la connexion d'enrôlement.
const dialTimeout = 10 * time.Second

// Identity est ce que le core a attribué au service.
type Identity struct {
	ComputeurID string
	ClientType  string
}

// Enroll déroule l'enrôlement complet et écrit l'identité sur disque.
//
// À la sortie : la paire de clés, la clé publique du core et client_software.yaml
// sont en place, et la connexion est fermée. Le service peut ouvrir une session
// ordinaire.
func Enroll() (Identity, error) {
	enroll := config.GetEnrollment()
	if strings.TrimSpace(enroll.Key) == "" {
		return Identity{}, fmt.Errorf("aucune clé d'enrôlement dans la configuration")
	}

	session, err := dialAnyServer()
	if err != nil {
		return Identity{}, err
	}
	defer func() {
		// La connexion se ferme dans TOUS les cas, y compris en cas d'erreur au
		// milieu du flux. Une connexion d'enrôlement laissée ouverte occuperait
		// une place côté core jusqu'à expiration, sans qu'aucune session n'en
		// sorte jamais.
		if cerr := session.Conn.Close(); cerr != nil {
			logs.Write_log("DEBUG", "enrôlement: fermeture de la connexion : "+cerr.Error())
		}
	}()

	// La clé publique du core est indispensable pour chiffrer 01_05.
	if !serveurauth.HaveServeurKey() {
		logs.Write_log("INFO", "enrôlement: clé publique du core absente, demande en cours")
		if !serveurauth.AskServerKey(session) {
			return Identity{}, fmt.Errorf("clé publique du core non obtenue")
		}
	}

	tmpKey := make([]byte, tmpKeyBytes)
	if _, err := rand.Read(tmpKey); err != nil {
		return Identity{}, fmt.Errorf("génération de la clé temporaire : %w", err)
	}

	identity, err := requestEnrollment(session, enroll, tmpKey)
	if err != nil {
		return Identity{}, err
	}

	// L'identité est écrite AVANT d'envoyer la clé publique.
	//
	// Si l'on écrivait après, une coupure entre 01_07 et 01_08 laisserait un
	// client créé côté core, un jeton consommé, et rien du tout côté service :
	// le prochain démarrage recommencerait un enrôlement et consommerait un
	// second jeton. Écrire d'abord rend la situation rattrapable.
	if err := config.SaveClientSoftware(identity.ComputeurID, identity.ClientType, false); err != nil {
		return Identity{}, err
	}

	publicPEM, err := keymanagement.GenerateClientKeyPair()
	if err != nil {
		return Identity{}, err
	}

	if err := sendPublicKey(session, identity, publicPEM); err != nil {
		return Identity{}, err
	}

	logs.Write_log("INFO", fmt.Sprintf(
		"enrôlement terminé : %s, type %s", identity.ComputeurID, identity.ClientType))
	return identity, nil
}

// dialAnyServer ouvre une connexion vers le premier core qui répond.
func dialAnyServer() (*storage.DuckySession, error) {
	servers := config.GetServers()
	if len(servers) == 0 {
		return nil, fmt.Errorf("aucun serveur configuré")
	}
	var lastErr error
	for _, server := range servers {
		addr := server.IP + ":" + strconv.Itoa(server.Port)
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			logs.Write_log("WARNING", "enrôlement: connexion impossible "+addr+" : "+err.Error())
			lastErr = err
			continue
		}
		logs.Write_log("INFO", "enrôlement: connecté à "+addr)
		return &storage.DuckySession{Conn: conn, IsSafe: false}, nil
	}
	return nil, fmt.Errorf("aucun serveur joignable : %v", lastErr)
}
