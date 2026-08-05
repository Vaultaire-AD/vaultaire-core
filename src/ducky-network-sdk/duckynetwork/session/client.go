package session

import (
	"fmt"

	"duckynetwork/duckynetwork/keymanagement"
	"duckynetwork/duckynetwork/storage"
	serveurauth "duckynetwork/duckynetwork/trames/t01_serveurauth"
	userauth "duckynetwork/duckynetwork/trames/t02_userauth"
	sshauth "duckynetwork/duckynetwork/trames/t03_ssh"
	tramesmanager "duckynetwork/duckynetwork/trames_manager"
)

// Client tient l'état d'un programme relié au core.
type Client struct {
	cfg     Config
	store   *keymanagement.Store
	spliter *tramesmanager.Spliter
	session *storage.DuckySession

	auth *userauth.Manager
	ssh  *sshauth.Pending
}

// New construit un Client sans ouvrir de connexion.
//
// Les catégories 01, 02 et 03 sont branchées d'office : elles forment le socle
// de connexion, identique pour tout programme. Un programme qui a besoin d'un
// traitement particulier — un agent qui provisionne un compte local à la
// réception d'un 03_02 — fournit son propre Spliter avec ses gestionnaires déjà
// posés : ce qui est déjà branché n'est pas remplacé.
func New(cfg Config) (*Client, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	store, err := keymanagement.NewStore(cfg.KeyDir)
	if err != nil {
		return nil, fmt.Errorf("répertoire de clés inutilisable : %w", err)
	}

	client := &Client{
		cfg:     cfg,
		store:   store,
		spliter: cfg.Spliter,
		auth:    &userauth.Manager{MachineInfo: cfg.MachineInfo},
		ssh:     &sshauth.Pending{},
	}
	if client.spliter == nil {
		client.spliter = tramesmanager.NewSpliter()
	}
	if !client.spliter.Handled("01") {
		client.spliter.Handle("01", serveurauth.Handler)
	}
	if !client.spliter.Handled("02") {
		client.spliter.Handle("02", client.auth.Handler)
	}
	if !client.spliter.Handled("03") {
		client.spliter.Handle("03", client.ssh.Handler)
	}
	return client, nil
}

// Spliter donne accès à l'aiguilleur pour y brancher des gestionnaires.
func (c *Client) Spliter() *tramesmanager.Spliter { return c.spliter }

// Session renvoie la session courante, ou nil hors connexion.
func (c *Client) Session() *storage.DuckySession { return c.session }

// Store donne accès au magasin de clés.
func (c *Client) Store() *keymanagement.Store { return c.store }

// SSH donne accès au registre de la catégorie 03.
//
// C'est par lui que passe l'authentification d'un utilisateur TIERS :
//
//	answer, err := sshauth.Authenticate(ctx, client.SSH(), client.Session(), user, password)
func (c *Client) SSH() *sshauth.Pending { return c.ssh }
