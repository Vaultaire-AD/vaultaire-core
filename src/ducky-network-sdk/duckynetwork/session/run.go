package session

import (
	"context"
	"errors"
	"time"

	"duckynetwork/duckynetwork/logs"
	serveurauth "duckynetwork/duckynetwork/trames/t01_serveurauth"
	tramesmanager "duckynetwork/duckynetwork/trames_manager"
)

// Run connecte, authentifie, lit, et reconnecte jusqu'à l'annulation du contexte.
//
// # Ce qui déclenche quoi
//
//   - coupure réseau ou erreur de lecture → nouvelle tentative, délai doublé ;
//   - serveur qui échoue au défi 01 → ARRÊT, sans réessai ;
//   - identité refusée → effacement local et réenrôlement si AllowReEnroll,
//     arrêt sinon ;
//   - contexte annulé → sortie propre.
//
// Le délai double à chaque échec parce qu'un core en train de redémarrer n'a
// rien à gagner à recevoir une tentative par seconde de chaque programme du
// parc. Il est remis à sa valeur initiale dès qu'une session tient.
func (c *Client) Run(ctx context.Context) error {
	delay := c.cfg.ReconnectDelay

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		err := c.runOnce(ctx)
		switch {
		case err == nil, errors.Is(err, context.Canceled):
			return nil

		case errors.Is(err, serveurauth.ErrServerNotAuthentic):
			// On ne réessaie PAS. Le serveur en face n'a pas su relever le
			// défi : soit ce n'est pas le core, soit sa clé a changé sans
			// qu'on le sache. Dans les deux cas, reconnecter en boucle ne fait
			// que redonner des occasions à qui se fait passer pour lui.
			return err

		case errors.Is(err, serveurauth.ErrIdentityRejected):
			if resetErr := c.selfReset(); resetErr != nil {
				return resetErr
			}
			// Réessai immédiat : le réenrôlement n'a pas de raison d'attendre,
			// et le délai courant vient d'échecs d'une identité qui n'existe
			// plus.
			delay = c.cfg.ReconnectDelay

		default:
			logs.Write("WARNING", "session perdue : "+err.Error())
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		if delay *= 2; delay > c.cfg.MaxReconnectDelay {
			delay = c.cfg.MaxReconnectDelay
		}
	}
}

// runOnce tient une connexion, du premier octet à sa perte.
//
// Un SEUL lecteur tourne sur la connexion, du début à la fin. L'authentification
// 02 s'appuie dessus au lieu d'ouvrir sa propre lecture : deux lecteurs
// concurrents se voleraient des trames au hasard de l'ordonnancement.
func (c *Client) runOnce(ctx context.Context) error {
	if err := c.Connect(); err != nil {
		return err
	}
	defer c.Close()

	privateKey, err := c.store.GetClientPrivateKey()
	if err != nil {
		return err
	}
	serverKey, err := c.store.GetServeurPublicKey()
	if err != nil {
		return err
	}

	// L'annulation du contexte ferme la connexion : c'est le seul moyen de
	// débloquer une lecture en cours, qui attend sans regarder le contexte.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			c.Close()
		case <-done:
		}
	}()

	readerErr := make(chan error, 1)
	go func() {
		for {
			if err := tramesmanager.MessageReader(c.session, privateKey, serverKey, c.spliter); err != nil {
				readerErr <- err
				return
			}
		}
	}()

	if err := c.Login(ctx); err != nil {
		// Une erreur de lecture explique mieux l'échec qu'un dépassement de
		// délai : si la connexion est tombée pendant l'authentification, c'est
		// cela qu'il faut lire dans les journaux, pas « délai dépassé ».
		select {
		case readErr := <-readerErr:
			return readErr
		default:
		}
		return err
	}

	if c.cfg.OnReady != nil {
		if err := c.cfg.OnReady(c.session); err != nil {
			return err
		}
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-readerErr:
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}
}
