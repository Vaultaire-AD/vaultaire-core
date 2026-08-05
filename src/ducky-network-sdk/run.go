package duckynetwork

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ServiceConfig décrit tout ce dont un client service a besoin pour vivre.
type ServiceConfig struct {
	CoreAddress        string
	ServerPublicKeyPEM string

	// EnrollmentKey n'est utilisée qu'en l'absence d'identité, ou après une
	// auto-réinitialisation. Une fois enrôlé, le service ne s'en sert plus.
	EnrollmentKey string

	// IdentityPath est le fichier où l'identité est persistée.
	IdentityPath string

	// Label est un nom lisible, pour les journaux du core. Aucune valeur de
	// sécurité.
	Label string

	Info              ServiceInfo
	HeartbeatInterval time.Duration

	// Logf reçoit les événements. Laissé nil, le SDK est muet : c'est au
	// programme hôte de décider où vont ses journaux.
	Logf func(level, message string)
}

func (cfg ServiceConfig) logf(level, format string, args ...any) {
	if cfg.Logf == nil {
		return
	}
	cfg.Logf(level, fmt.Sprintf(format, args...))
}

// RunService fait vivre un client service jusqu'à l'annulation du contexte.
//
// # Le cycle
//
//	identité absente ?      -> enrôlement
//	connexion               -> 01_01 / 01_02
//	enregistrement          -> 04_09
//	battement de cœur       -> 04_12, en boucle
//	arrêt                   -> 04_14
//
// # L'auto-réinitialisation
//
// Si le core refuse notre identité — clé publique remplacée, client supprimé
// pour inactivité prolongée —, réessayer avec la même paire ne mènera jamais
// nulle part. Le SDK efface alors l'identité et se réenrôle avec la clé de
// configuration.
//
// C'est délibérément conditionné à ErrIdentityRejected et à rien d'autre. Un core
// injoignable, une coupure réseau ou une erreur de lecture ne doivent PAS
// déclencher de réenrôlement : ils consommeraient une utilisation de clé à chaque
// incident, et une clé à usage unique serait épuisée par la première panne
// réseau.
func RunService(ctx context.Context, cfg ServiceConfig) error {
	if cfg.IdentityPath == "" {
		return fmt.Errorf("identity_path requis")
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = DefaultHeartbeatInterval
	}

	backoff := newBackoff()

	for {
		if err := ctx.Err(); err != nil {
			return nil
		}

		err := runOnce(ctx, cfg)
		switch {
		case err == nil || errors.Is(err, context.Canceled):
			return nil

		case errors.Is(err, ErrIdentityRejected):
			cfg.logf("WARNING", "identité refusée par le core : réinitialisation et réenrôlement")
			if resetErr := ResetIdentity(cfg.IdentityPath); resetErr != nil {
				cfg.logf("ERROR", "réinitialisation impossible : %v", resetErr)
			}
			// Pas d'attente : l'identité vient d'être effacée, la tentative
			// suivante est un enrôlement, pas une redite de ce qui a échoué.
			backoff.reset()

		default:
			wait := backoff.next()
			cfg.logf("WARNING", "cycle interrompu (%v) — nouvelle tentative dans %s", err, wait)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(wait):
			}
		}
	}
}

// runOnce enrôle si besoin, se connecte, s'enregistre et bat jusqu'à l'échec.
func runOnce(ctx context.Context, cfg ServiceConfig) error {
	identity, err := LoadIdentity(cfg.IdentityPath)
	if err != nil {
		return err
	}

	if !identity.Valid() {
		if cfg.EnrollmentKey == "" {
			return fmt.Errorf("%w: aucune identité et aucune clé d'enrôlement en configuration", ErrNotEnrolled)
		}
		cfg.logf("INFO", "aucune identité : enrôlement auprès de %s", cfg.CoreAddress)
		identity, err = Enroll(cfg.CoreAddress, cfg.ServerPublicKeyPEM, cfg.EnrollmentKey, cfg.Label)
		if err != nil {
			return err
		}
		if err := SaveIdentity(cfg.IdentityPath, identity); err != nil {
			// L'identité est perdue si on continue : le service tournerait, puis
			// se réenrôlerait au prochain démarrage, consommant une clé à chaque
			// fois. Mieux vaut échouer maintenant, bruyamment.
			return fmt.Errorf("identité obtenue mais non enregistrée : %w", err)
		}
		cfg.logf("INFO", "enrôlé comme %s (type %s)", identity.ComputeurID, identity.ClientType)
	}

	client, err := NewClient(ClientOpts{
		CoreAddress:     cfg.CoreAddress,
		ComputeurID:     identity.ComputeurID,
		PrivateKeyPEM:   identity.PrivateKey,
		ServerPubKeyPEM: cfg.ServerPublicKeyPEM,
	})
	if err != nil {
		return err
	}
	if err := client.Connect(); err != nil {
		return err
	}
	defer func() {
		if err := client.DeregisterService(); err != nil {
			cfg.logf("DEBUG", "sortie propre non envoyée : %v", err)
		}
		_ = client.Close()
	}()

	info := cfg.Info
	if info.Endpoint == "" {
		info.Endpoint = client.LocalIP()
	}
	if err := client.RegisterService(info); err != nil {
		return err
	}
	cfg.logf("INFO", "service %s enregistré dans le cluster", identity.ComputeurID)

	ticker := time.NewTicker(cfg.HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			err := client.ServiceHeartbeat()
			switch {
			case err == nil:
			case errors.Is(err, ErrServiceUnknown):
				// Le core ne nous connaît plus comme service enregistré, mais
				// notre identité reste valide : il suffit de rejouer 04_09.
				cfg.logf("WARNING", "service inconnu du cluster : réenregistrement")
				if err := client.RegisterService(info); err != nil {
					return err
				}
			default:
				return err
			}
		}
	}
}

// backoff espace les tentatives après un échec.
//
// Plafonné : au-delà, allonger encore ne soulage plus le core et retarde
// seulement le retour du service quand la panne se résout.
type backoff struct {
	current time.Duration
}

func newBackoff() *backoff { return &backoff{current: 0} }

func (b *backoff) reset() { b.current = 0 }

func (b *backoff) next() time.Duration {
	const (
		first = 2 * time.Second
		max   = 2 * time.Minute
	)
	if b.current == 0 {
		b.current = first
		return b.current
	}
	b.current *= 2
	if b.current > max {
		b.current = max
	}
	return b.current
}
