package session

import (
	"fmt"
	"strings"

	"vaultaire_proxy/duckynetwork/logs"
)

// selfReset efface l'identité locale pour repartir d'un enrôlement.
//
// # Quand cela arrive
//
// Le core répond à 01_01 en chiffrant avec la clé publique de l'identifiant
// annoncé. Ne pas savoir lire sa réponse signifie que notre paire ne correspond
// plus à ce qu'il détient : client supprimé, base réinstallée, clés régénérées.
// Aucune quantité de tentatives ne réparera cela.
//
// # Pourquoi ce n'est PAS automatique par défaut
//
// Se réenrôler après une révocation reviendrait à contourner la décision d'un
// administrateur. Le réenrôlement demande une clé d'enrôlement valide : celui
// qui coupe l'accès peut aussi révoquer la clé, mais tant qu'il ne l'a pas fait,
// un programme trop obstiné reprendrait sa place. AllowReEnroll doit donc être
// un choix explicite du programme hôte.
//
// La clé publique du core est CONSERVÉE : ce n'est pas elle qui est en cause, et
// la redemander en clair rouvrirait la seule fenêtre du protocole où un
// intermédiaire pourrait substituer la sienne.
func (c *Client) selfReset() error {
	if !c.cfg.AllowReEnroll {
		return fmt.Errorf("identité refusée par le core et réenrôlement non autorisé")
	}
	if strings.TrimSpace(c.cfg.EnrollmentKey) == "" {
		return fmt.Errorf("identité refusée par le core et aucune clé d'enrôlement disponible")
	}
	if err := c.store.Reset(); err != nil {
		return fmt.Errorf("effacement de l'identité locale : %w", err)
	}
	logs.Write("WARNING", "identité locale effacée, réenrôlement au prochain essai")
	return nil
}
