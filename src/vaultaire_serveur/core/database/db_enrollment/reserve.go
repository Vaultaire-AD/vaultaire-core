package dbenrollment

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"vaultaire/core/logs"
)

// Motifs de refus. Ils sont distincts DANS LES JOURNAUX du serveur, et
// volontairement indistincts pour le client, qui reçoit un refus unique.
//
// Répondre « expirée » plutôt que « inconnue » transformerait le point
// d'enrôlement en oracle : l'attaquant apprendrait qu'une clé a existé, donc que
// son format est le bon, donc où concentrer ses essais.
var (
	ErrUnknownKey   = errors.New("clé d'enrôlement inconnue")
	ErrExpiredKey   = errors.New("clé d'enrôlement expirée")
	ErrExhaustedKey = errors.New("quota d'utilisations atteint")
	ErrRevokedKey   = errors.New("clé d'enrôlement révoquée")
)

// Reservation est une utilisation décomptée, en attente de confirmation.
type Reservation struct {
	KeyID      int
	ClientType string
}

// Reserve décompte une utilisation et retourne le type porté par la clé.
//
// # Pourquoi décompter AVANT de créer le client
//
// L'enrôlement est en deux temps : décompter ici, puis créer le client, puis
// confirmer avec Confirm. Les deux ordres possibles ont un mode d'échec, et ils
// ne se valent pas :
//
//   - créer d'abord, décompter ensuite : une panne entre les deux laisse un
//     client enregistré sans qu'aucune clé n'ait été consommée. Une clé à usage
//     unique en produirait deux.
//   - décompter d'abord, créer ensuite : une panne entre les deux consomme une
//     utilisation sans créer de client. On perd un jeton, personne n'entre.
//
// Le second est le seul acceptable pour une frontière de privilège. Release
// rattrape le cas courant — l'échec de création — et la perte ne subsiste que
// si le serveur tombe entre les deux instructions.
//
// # Atomicité
//
// Le décompte est fait par un UPDATE conditionnel dont la garde est dans le
// WHERE. Deux enrôlements simultanés sur une clé à usage unique ne peuvent donc
// pas réussir tous les deux : le moteur sérialise, le second ne touche aucune
// ligne. Un SELECT suivi d'un UPDATE aurait laissé la fenêtre ouverte.
func Reserve(db *sql.DB, secret string) (Reservation, error) {
	if db == nil {
		return Reservation{}, fmt.Errorf("connexion base indisponible")
	}
	hash := HashSecret(secret)
	now := time.Now().UTC()

	res, err := db.Exec(
		// max_uses = 0 vaut « illimité », expires_at NULL vaut « sans
		// expiration ». Les deux gardes restent DANS le WHERE : les sortir pour
		// les évaluer en Go rouvrirait la fenêtre entre lecture et écriture que
		// cet UPDATE conditionnel existe précisément pour fermer.
		`UPDATE service_enrollment_key
		    SET used_count = used_count + 1
		  WHERE key_hash   = ?
		    AND revoked_at IS NULL
		    AND (max_uses   = 0 OR used_count < max_uses)
		    AND (expires_at IS NULL OR expires_at > ?)`,
		hash, now)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: décompte échoué : "+err.Error())
		return Reservation{}, fmt.Errorf("consommation de la clé : %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return Reservation{}, fmt.Errorf("consommation de la clé : %w", err)
	}

	if affected == 0 {
		// Le décompte a échoué : on relit la ligne pour journaliser la vraie
		// raison. Cette lecture n'est faite QUE sur le chemin d'échec, pour que
		// le cas courant reste une seule instruction.
		return Reservation{}, diagnose(db, hash, now)
	}

	var r Reservation
	if err := db.QueryRow(
		`SELECT id_key, client_type FROM service_enrollment_key WHERE key_hash = ?`,
		hash).Scan(&r.KeyID, &r.ClientType); err != nil {
		// La ligne vient d'être mise à jour : son absence ici signale une
		// suppression concurrente, pas un cas normal. L'utilisation est perdue,
		// et c'est le bon sens de l'erreur.
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: relecture après décompte : "+err.Error())
		return Reservation{}, fmt.Errorf("relecture de la clé : %w", err)
	}
	return r, nil
}

// diagnose détermine pourquoi une clé n'a pas pu être consommée.
func diagnose(db *sql.DB, hash string, now time.Time) error {
	var (
		revoked   sql.NullTime
		usedCount int
		maxUses   int
		expiresAt sql.NullTime
	)
	err := db.QueryRow(
		`SELECT revoked_at, used_count, max_uses, expires_at
		   FROM service_enrollment_key WHERE key_hash = ?`, hash).
		Scan(&revoked, &usedCount, &maxUses, &expiresAt)
	switch {
	case err == sql.ErrNoRows:
		return ErrUnknownKey
	case err != nil:
		return fmt.Errorf("diagnostic de la clé : %w", err)
	case revoked.Valid:
		return ErrRevokedKey
	case maxUses > 0 && usedCount >= maxUses:
		return ErrExhaustedKey
	case expiresAt.Valid && !now.Before(expiresAt.Time):
		return ErrExpiredKey
	default:
		// Ni révoquée, ni épuisée, ni expirée, mais l'UPDATE n'a rien touché :
		// une transaction concurrente est passée entre les deux. Traité comme
		// un épuisement, qui est l'issue la plus probable et la plus sûre.
		return ErrExhaustedKey
	}
}

// Confirm enregistre la consommation une fois le client créé.
//
// Échouer ici ne remet pas le compteur en arrière : le client existe, la clé a
// bien servi. Seule la trace d'audit est perdue, ce qui est journalisé.
func Confirm(db *sql.DB, r Reservation, computeurID, sourceIP string) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	var ip any
	if sourceIP != "" {
		ip = sourceIP
	}
	if _, err := db.Exec(
		`INSERT INTO service_enrollment_use (d_id_key, computeur_id, client_type, source_ip)
		 VALUES (?, ?, ?, ?)`,
		r.KeyID, computeurID, r.ClientType, ip); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"dbenrollment: trace de consommation non écrite pour "+computeurID+" : "+err.Error())
		return fmt.Errorf("trace de consommation : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"enrôlement: service %s de type %s enrôlé avec la clé %d depuis %s",
		computeurID, r.ClientType, r.KeyID, orUnknown(sourceIP)))
	return nil
}

// Release rend l'utilisation décomptée quand la création du client a échoué.
func Release(db *sql.DB, r Reservation) error {
	if db == nil {
		return fmt.Errorf("connexion base indisponible")
	}
	// used_count > 0 évite qu'un double appel ne descende sous zéro et ne
	// rouvre silencieusement une clé épuisée.
	if _, err := db.Exec(
		`UPDATE service_enrollment_key
		    SET used_count = used_count - 1
		  WHERE id_key = ? AND used_count > 0`, r.KeyID); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery, "dbenrollment: restitution échouée : "+err.Error())
		return fmt.Errorf("restitution de l'utilisation : %w", err)
	}
	logs.Write_Log("WARNING", fmt.Sprintf(
		"enrôlement: utilisation rendue sur la clé %d — la création du client a échoué", r.KeyID))
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "origine inconnue"
	}
	return s
}
