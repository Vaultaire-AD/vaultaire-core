package duckynetwork

import (
	"fmt"
	"strings"
	"time"
)

// ServiceInfo décrit ce qu'un client service déclare au cluster.
//
// Les capacités sont de l'INVENTAIRE et n'accordent aucun droit : ce qu'un
// service peut émettre est décidé par son type au catalogue, côté core. Un champ
// déclaratif qui accorderait quoi que ce soit serait une élévation de privilèges
// offerte au client.
type ServiceInfo struct {
	Version      string
	Endpoint     string
	Capabilities []string
}

// RegisterService envoie 04_09 et attend 04_10.
func (c *Client) RegisterService(info ServiceInfo) error {
	if info.Version == "" || info.Endpoint == "" {
		return fmt.Errorf("version et endpoint requis pour s'enregistrer")
	}
	resp, err := c.Send(Frame{
		Code:    Trame04_09,
		Content: info.Version + "\n" + info.Endpoint + "\n" + strings.Join(info.Capabilities, ","),
	})
	if err != nil {
		return fmt.Errorf("enregistrement du service : %w", err)
	}
	switch resp.Code {
	case Trame04_10:
		return nil
	case Trame04_11:
		return fmt.Errorf("enregistrement refusé : %s — %s", resp.Line(0), resp.Line(1))
	default:
		return fmt.Errorf("réponse inattendue à l'enregistrement : %s", resp.Code)
	}
}

// ServiceHeartbeat envoie 04_12 et attend 04_13.
//
// Un refus « unknown_service » n'est pas une panne : le core a été réinstallé, ou
// le service a été purgé pour inactivité. Il est remonté tel quel pour que
// l'appelant rejoue son enregistrement plutôt que de battre dans le vide.
func (c *Client) ServiceHeartbeat() error {
	resp, err := c.Send(Frame{Code: Trame04_12})
	if err != nil {
		return fmt.Errorf("battement de cœur : %w", err)
	}
	switch resp.Code {
	case Trame04_13:
		return nil
	case Trame04_11:
		return fmt.Errorf("%w: %s", ErrServiceUnknown, resp.Line(1))
	default:
		return fmt.Errorf("réponse inattendue au battement : %s", resp.Code)
	}
}

// DeregisterService envoie 04_14 avant l'arrêt.
//
// Sans elle, un arrêt planifié serait indistinguable d'une panne pendant toute la
// fenêtre de battement de cœur.
func (c *Client) DeregisterService() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isSafe {
		return nil
	}
	frame := Frame{
		Code:     Trame04_14,
		Target:   TargetCore,
		Session:  string(c.sessKey),
		Username: c.opts.Username,
		ClientID: c.opts.ComputeurID,
	}
	// Aucune réponse n'est attendue : le core ne répond rien à 04_14, et
	// l'attendre bloquerait l'arrêt jusqu'au délai de lecture.
	return c.sendSecure(frame.Build())
}

// ErrServiceUnknown : le core ne connaît pas ce service enregistré.
var ErrServiceUnknown = fmt.Errorf("service inconnu du cluster")

// DefaultHeartbeatInterval est la période d'émission du battement.
//
// Inférieure au seuil de péremption du core (trois minutes) avec une marge :
// deux battements peuvent se perdre sans que le service soit déclaré hors ligne.
const DefaultHeartbeatInterval = 45 * time.Second
