package dbrevocation

import (
	"database/sql"
	"fmt"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
)

// LiftSoftRevocations lève les verrouillages soft actifs d'un compte.
//
// Retourne le nombre de verrous levés, pour distinguer « déverrouillé » de
// « n'était pas verrouillé » — l'interface ne doit pas annoncer une action qui
// n'a rien changé.
//
// # Les machines qui n'avaient pas acquitté le verrouillage
//
// Leur cible passe à « lifted » : l'ordre de verrouillage ne leur sera plus
// remis (TO-DO 49). Elles reçoivent la LEVÉE, qui est un ordre à part entière
// et suffit — sur une machine qui n'avait jamais verrouillé, elle ne trouve rien
// à faire ; sur une machine qui avait verrouillé sans réussir à couper les
// processus, elle rouvre.
//
// Sans cela, une machine ayant acquitté la levée mais pas le verrouillage
// gardait celui-ci « à rejouer ». Rejoué seul, il refermait le compte local
// d'une personne que l'annuaire dit rétablie — et rien ne le rouvrait, la levée
// étant déjà acquittée.
func LiftSoftRevocations(db *sql.DB, username, liftedBy string) (int, error) {
	if err := database.SanitizeIdentifier(username, liftedBy); err != nil {
		return 0, err
	}

	// Les cibles d'abord, tant que « lifted_at IS NULL » désigne encore les
	// verrouillages qu'on va lever. Dans l'autre sens, une interruption entre
	// les deux écritures laisserait des verrouillages levés ET rejouables —
	// exactement le défaut. Dans ce sens-ci, elle laisse un verrouillage en
	// vigueur dont les machines en retard ne recevront plus l'ordre : la levée,
	// relancée, répare ; et le compte reste fermé côté serveur d'ici là.
	if _, err := db.Exec(
		`UPDATE user_revocation_target t
		   JOIN user_revocation r ON r.id_revocation = t.d_id_revocation
		    SET t.status = ?
		  WHERE r.username = ? AND r.mode = ? AND r.lifted_at IS NULL AND `+sqlARejouer,
		string(revocation.StatusLifted), username, string(revocation.ModeSoft)); err != nil {
		return 0, fmt.Errorf("rangement des cibles du verrouillage levé : %w", err)
	}

	res, err := db.Exec(
		`UPDATE user_revocation SET lifted_by = ?, lifted_at = NOW()
		 WHERE username = ? AND mode = ? AND lifted_at IS NULL`,
		liftedBy, username, string(revocation.ModeSoft))
	if err != nil {
		return 0, fmt.Errorf("levée du verrouillage : %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"revocation: verrouillage de %s levé par %s (%d ordre(s))", username, liftedBy, affected))
	}
	return int(affected), nil
}
