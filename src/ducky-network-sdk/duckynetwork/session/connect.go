package session

import (
	"context"
	"fmt"
	"net"
	"time"

	"duckynetwork/duckynetwork/logs"
	"duckynetwork/duckynetwork/storage"
	serveurauth "duckynetwork/duckynetwork/trames/t01_serveurauth"
	userauth "duckynetwork/duckynetwork/trames/t02_userauth"
)

// dialTimeout borne l'établissement de la connexion TCP.
const dialTimeout = 15 * time.Second

// Connect ouvre une session prête à l'emploi.
//
// # L'ordre des étapes n'est pas interchangeable
//
//  0. connexion TCP, sans quoi rien ne peut être demandé
//  1. clé publique du core, sans quoi rien ne peut être chiffré
//  2. enrôlement SI aucune identité n'existe — il produit la paire de clés
//  01. poignée de main : le SERVEUR est authentifié, la clé de session est posée
//  02. authentification : le PROGRAMME est authentifié auprès du serveur
//
// Les deux dernières sont les deux moitiés d'une même chose, et elles vont
// toujours ensemble. Une session arrêtée après 01 a un tunnel chiffré mais
// aucune identité reconnue côté core : elle sera refusée à la première trame
// utile, avec un message qui ne dira pas que le login manque.
//
// C'est pour cela que Connect ne rend la main qu'après 02, et non après 01.
//
// Connect ferme la connexion en cas d'échec : une connexion à demi établie
// occuperait une place côté core jusqu'à expiration.
func (c *Client) Connect() error {
	conn, err := net.DialTimeout("tcp", c.cfg.ServerAddress, dialTimeout)
	if err != nil {
		return fmt.Errorf("connexion à %s : %w", c.cfg.ServerAddress, err)
	}
	session := &storage.DuckySession{Conn: conn}

	if err := c.bootstrap(session); err != nil {
		conn.Close()
		return err
	}
	c.session = session
	return nil
}

// bootstrap couvre les étapes 0 à 01 : clé du core, identité, poignée de main.
func (c *Client) bootstrap(session *storage.DuckySession) error {
	serverKey, err := serveurauth.EnsureServerKey(session, c.store)
	if err != nil {
		return err
	}

	identity, err := c.store.LoadIdentity()
	if err != nil || !identity.Valid() || !c.store.HasClientKeys() {
		identity, err = serveurauth.Enroll(
			session, c.store, serverKey, c.cfg.EnrollmentKey, c.cfg.Label)
		if err != nil {
			return err
		}
	}
	session.ComputeurID = identity.ComputeurID
	session.ClientType = identity.ClientType
	session.Username = c.loginUsername()

	privateKey, err := c.store.GetClientPrivateKey()
	if err != nil {
		return fmt.Errorf("clé privée illisible : %w", err)
	}
	return serveurauth.Handshake(session, serverKey, privateKey)
}

// Close ferme la connexion courante.
func (c *Client) Close() {
	if c.session != nil && c.session.Conn != nil {
		c.session.Conn.Close()
	}
	c.session = nil
}

// loginUsername rend le compte sous lequel s'authentifier.
func (c *Client) loginUsername() string {
	if c.cfg.Username != "" {
		return c.cfg.Username
	}
	return userauth.ServiceAccount
}

// loginPassword rend le secret associé.
func (c *Client) loginPassword() string {
	if c.cfg.Username != "" {
		return c.cfg.Password
	}
	return userauth.ServiceAccount
}

// Login exécute l'étape 02 et attend son issue.
//
// # Elle ne lit PAS la connexion
//
// Le défi 02_02 puis la réponse 02_04 ou 02_11 arrivent par la boucle de
// réception ordinaire, qui doit donc déjà tourner quand Login est appelée. C'est
// Run qui s'en charge.
//
// Lire ici en plus donnerait deux lecteurs sur la même connexion : ils se
// voleraient des trames au hasard de l'ordonnancement, et la panne ne se
// reproduirait qu'une fois sur dix.
func (c *Client) Login(ctx context.Context) error {
	c.auth.Reset()

	if err := userauth.AskAuthentification(c.session, c.loginUsername(), c.loginPassword()); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(ctx, c.cfg.AuthTimeout)
	defer cancel()

	result, err := c.auth.Wait(ctx)
	if err != nil {
		return fmt.Errorf("authentification : %w", err)
	}
	logs.Write("INFO", "authentifié auprès du core comme "+result.Username)
	return nil
}
