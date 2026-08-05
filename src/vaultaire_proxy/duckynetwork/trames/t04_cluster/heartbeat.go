package cluster

import (
	"context"
	"fmt"
	"time"

	"vaultaire_proxy/duckynetwork/logs"
	"vaultaire_proxy/duckynetwork/sendmessage"
	"vaultaire_proxy/duckynetwork/storage"
)

// DefaultHeartbeatPeriod est la période d'émission recommandée.
//
// Le core bascule un service hors ligne après trois minutes sans battement. Une
// minute laisse donc rater deux battements avant l'alarme : une latence réseau
// ne devient pas un incident, et une vraie panne se voit en trois minutes.
const DefaultHeartbeatPeriod = time.Minute

// SendHeartbeat envoie un unique 04_12.
func SendHeartbeat(session *storage.DuckySession) error {
	message := sendmessage.BuildClientTrame(
		Heartbeat, "serveur_central", session.SessionID, session.Username, session.ComputeurID)
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		return fmt.Errorf("envoi de 04_12 : %w", err)
	}
	return nil
}

// RunHeartbeat bat jusqu'à l'annulation du contexte ou la première erreur d'envoi.
//
// Une erreur d'envoi rend la main plutôt que de réessayer : elle signifie que la
// connexion est tombée, et c'est à la boucle de session — qui sait reconnecter,
// et au besoin se réenrôler — de décider de la suite. Réessayer ici masquerait
// la panne à celui qui peut la traiter.
func RunHeartbeat(ctx context.Context, session *storage.DuckySession, period time.Duration) error {
	if period <= 0 {
		period = DefaultHeartbeatPeriod
	}
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := SendHeartbeat(session); err != nil {
				logs.Write("WARNING", "battement de cœur interrompu : "+err.Error())
				return err
			}
		}
	}
}

// Deregister envoie 04_14 : sortie propre à l'arrêt.
//
// Sans elle, un arrêt planifié serait indistinguable d'une panne pendant toute
// la fenêtre de battement. Le core ne répond rien ; l'erreur est journalisée et
// non remontée, puisqu'on est déjà en train de s'arrêter.
func Deregister(session *storage.DuckySession) {
	message := sendmessage.BuildClientTrame(
		DeregisterService, "serveur_central", session.SessionID, session.Username, session.ComputeurID)
	if err := sendmessage.SendMessage(message, session, ""); err != nil {
		logs.Write("DEBUG", "sortie du cluster non transmise : "+err.Error())
	}
}
