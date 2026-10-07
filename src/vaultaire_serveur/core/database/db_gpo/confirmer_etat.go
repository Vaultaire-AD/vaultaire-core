package dbgpo

import (
	"database/sql"
	"fmt"
	"time"

	"vaultaire/core/database"
)

// ConfirmerEtat rafraîchit la date d'une portée dont l'agent vient de confirmer
// qu'elle est à jour — TO-DO 166.
//
// # Le défaut
//
// `reported_at` n'était écrit que par le rapport d'APPLICATION. Or un agent dont
// la politique n'a pas bougé n'applique rien : il demande, le core répond « rien
// à faire » (05_03, 05_07), et aucun rapport ne part. La date restait donc celle
// de la dernière fois où quelque chose avait changé.
//
// Trois cycles plus tard, la machine passait « en retard » — et y restait. Un
// parc stable, c'est-à-dire un parc qui va bien, s'affichait en retard tout
// entier, et le résumé disait « N en retard » à la place de « toutes à jour ».
// La colonne faite pour repérer l'agent qui s'est tu désignait tous ceux qui
// n'avaient rien de neuf à dire.
//
// # Pourquoi c'est bien un rapport
//
// La demande porte l'empreinte que la machine APPLIQUE ; le core ne répond
// « rien à faire » que si elle égale celle de la politique effective. À cet
// instant, il sait donc que la machine est à cette empreinte — exactement ce
// qu'un rapport d'application lui aurait dit.
//
// # Seulement la ligne qui porte CETTE empreinte
//
// Si la ligne en base en porte une autre — un rapport d'application perdu — la
// dater d'aujourd'hui ferait passer pour fraîches des colonnes qui décrivent
// une application antérieure. On ne touche à rien, et la machine reste
// signalée : c'est vrai qu'on ne sait pas ce qu'elle a fait de la dernière.
//
// Les colonnes de dérive ne sont pas touchées, pour la raison dite dans
// SaveApplyReport : elles viennent du scan, qui a son propre rythme.
func ConfirmerEtat(db *sql.DB, computeurID, scope, targetUser, fingerprint string) error {
	if db == nil {
		return fmt.Errorf("gpo: connexion base indisponible")
	}
	if err := database.SanitizeIdentifier(computeurID); err != nil {
		return err
	}
	if fingerprint == "" {
		return nil
	}
	if _, err := db.Exec(`
		UPDATE gpo_compliance
		   SET reported_at = ?
		 WHERE computeur_id = ? AND scope = ? AND target_user = ? AND fingerprint = ?`,
		time.Now().UTC(), computeurID, scope, targetUser, fingerprint); err != nil {
		return fmt.Errorf("gpo: confirmation de l'état : %w", err)
	}
	return nil
}
