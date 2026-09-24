package dbsessions

import (
	"database/sql"
	"fmt"

	database "vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Sessions utilisateur ouvertes par PAM — table `user_sessions`.
//
// # Ce que la table sépare, et pourquoi il fallait la séparer
//
// `did_login` veut dire « une session Ducky » : un tunnel, une clé, une
// connexion. `status -c` l'énumère pour dire quelles machines sont là.
//
// Le point 68 y a écrit les sessions PAM, faute de table où les mettre. Une
// machine sur laquelle quelqu'un travaille apparaissait alors DEUX fois dans
// `status -c`, alors qu'un seul tunnel existe (recette du 24/09). Les deux
// objets n'ont ni le même cycle de vie, ni la même clé, ni le même lecteur :
// une session PAM n'a pas de connexion à elle, elle vit dans le tunnel de sa
// machine.
//
// Une colonne d'origine dans `did_login` aurait suffi à les distinguer. Elle
// aurait aussi laissé un filtre à ne pas oublier dans chaque lecture, et la
// suivante serait retombée dans le piège.
//
// # Les lignes écrites par le point 68 n'ont pas besoin d'être migrées
//
// Elles vivent dans `did_login` avec une validité de dix minutes, et plus rien
// ne les prolonge maintenant que le battement ne touche que la ligne de la
// machine. La purge des sessions expirées les emporte donc d'elle-même, au
// pire dix minutes après la mise à jour du core. Écrire une migration pour
// distinguer ces lignes d'une session 02_03 légitime aurait été plus risqué que
// de les laisser s'éteindre.

// OuvrirSessionUtilisateur enregistre — ou rafraîchit — la session d'un compte
// sur une machine.
//
// Appelée après TOUS les contrôles d'une 03_01 réussie : une ligne écrite plus
// tôt ferait apparaître dans `status -u` quelqu'un à qui l'accès a été refusé.
func OuvrirSessionUtilisateur(db *sql.DB, username, computeurID string) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	idUser, idLogiciel, err := resoudreCompteEtMachine(db, username, computeurID)
	if err != nil {
		return err
	}

	// ON DUPLICATE KEY plutôt qu'un SELECT suivi d'un INSERT ou d'un UPDATE :
	// deux connexions du même compte sur la même machine peuvent arriver en
	// même temps (console et SSH), et le couple (compte, machine) est unique
	// en base. Laisser MySQL trancher évite la course.
	_, err = db.Exec(`
		INSERT INTO user_sessions (d_id_user, d_id_logiciel, opened_at, key_time_validity)
		VALUES (?, ?, NOW(), ?)
		ON DUPLICATE KEY UPDATE key_time_validity = VALUES(key_time_validity)`,
		idUser, idLogiciel, EcheanceSession())
	if err != nil {
		return fmt.Errorf("ouverture de session de %s sur %s : %w", username, computeurID, err)
	}
	return nil
}

// FermerSessionUtilisateur efface la session d'un compte sur une machine.
//
// Rend le nombre de lignes effacées : zéro n'est pas une erreur — une
// déconnexion peut arriver après l'expiration de la ligne, ou après un
// redémarrage du core.
func FermerSessionUtilisateur(db *sql.DB, username, computeurID string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("base indisponible")
	}
	idUser, idLogiciel, err := resoudreCompteEtMachine(db, username, computeurID)
	if err != nil {
		return 0, err
	}

	res, err := db.Exec(
		"DELETE FROM user_sessions WHERE d_id_user = ? AND d_id_logiciel = ?",
		idUser, idLogiciel)
	if err != nil {
		return 0, fmt.Errorf("fermeture de session de %s sur %s : %w", username, computeurID, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// FermerSessionsUtilisateurPartout efface toutes les sessions d'un compte, sur
// toutes les machines.
//
// Sert au kill switch : un compte révoqué ne doit pas rester affiché comme
// connecté. Cela ne ferme AUCUNE session ouverte sur les postes — la
// révocation a son propre canal pour cela (trames 06) — mais un tableau de
// bord qui montre encore un compte coupé est un tableau de bord qui ment.
func FermerSessionsUtilisateurPartout(db *sql.DB, username string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("base indisponible")
	}
	idUser, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return 0, fmt.Errorf("fermeture des sessions : compte %s introuvable : %w", username, err)
	}
	res, err := db.Exec("DELETE FROM user_sessions WHERE d_id_user = ?", idUser)
	if err != nil {
		return 0, fmt.Errorf("fermeture des sessions de %s : %w", username, err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ProlongerSessionsUtilisateurDeLaMachine repousse l'échéance des sessions
// utilisateur d'une machine.
//
// # Pourquoi c'est le battement de la MACHINE qui les prolonge
//
// Une session PAM n'a ni connexion ni clé propre : elle vit dans le tunnel de
// la machine. Rien ne peut donc la prolonger d'elle-même, et sans cet appel
// toute personne connectée disparaîtrait de `status -u` au bout de dix minutes
// alors qu'elle est devant son écran.
//
// La contrepartie est voulue : une machine éteinte cesse de battre, et ses
// sessions utilisateur expirent avec elle. C'est le seul mécanisme
// d'expiration qu'elles aient.
func ProlongerSessionsUtilisateurDeLaMachine(db *sql.DB, computeurID string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("base indisponible")
	}
	idLogiciel, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return 0, fmt.Errorf("prolongation des sessions : machine %s introuvable : %w", computeurID, err)
	}

	res, err := db.Exec(
		"UPDATE user_sessions SET key_time_validity = ? WHERE d_id_logiciel = ?",
		EcheanceSession(), idLogiciel)
	if err != nil {
		return 0, fmt.Errorf("prolongation des sessions de %s : %w", computeurID, err)
	}
	// Zéro ligne n'est pas une erreur : une machine qui bat sans session
	// utilisateur ouverte est le cas le plus courant du parc.
	n, _ := res.RowsAffected()
	return n, nil
}

// PurgerSessionsUtilisateurExpirees efface les sessions dont l'échéance est
// passée.
//
// La comparaison est faite par MySQL, comme pour did_login : le driver rend un
// TIMESTAMP dans un format que le code Go ne reparse pas de la même façon, et
// c'est le défaut qui avait rendu l'ancien nettoyage inopérant pendant des
// mois.
func PurgerSessionsUtilisateurExpirees(db *sql.DB) error {
	if db == nil {
		return fmt.Errorf("base indisponible")
	}
	res, err := db.Exec("DELETE FROM user_sessions WHERE key_time_validity < NOW()")
	if err != nil {
		return fmt.Errorf("purge des sessions utilisateur : %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		logs.Write_Log("INFO", fmt.Sprintf("%d session(s) utilisateur expirée(s) supprimée(s)", n))
	}
	return nil
}

// --- lectures ---------------------------------------------------------------

// requeteSessions est la lecture commune aux trois vues de `status -u`.
//
// Une seule requête, trois filtres : les trois vues doivent montrer la même
// chose du même objet, et trois requêtes écrites à la main finiraient par
// diverger sur une jointure ou une colonne.
const requeteSessions = `
	SELECT users.id_user, users.username, users.created_at,
	       user_sessions.key_time_validity, id_logiciels.computeur_id
	FROM user_sessions
	INNER JOIN users ON user_sessions.d_id_user = users.id_user
	INNER JOIN id_logiciels ON user_sessions.d_id_logiciel = id_logiciels.id_logiciel`

// ListerSessionsUtilisateur rend toutes les sessions utilisateur ouvertes.
func ListerSessionsUtilisateur(db *sql.DB) ([]storage.UserConnected, error) {
	return lireSessions(db, requeteSessions+" ORDER BY users.username, id_logiciels.computeur_id")
}

// SessionsDUnUtilisateur rend les sessions d'un compte, sur toutes ses machines.
func SessionsDUnUtilisateur(db *sql.DB, username string) ([]storage.UserConnected, error) {
	if injection := database.SanitizeIdentifier(username); injection != nil {
		return nil, injection
	}
	return lireSessions(db, requeteSessions+
		" WHERE users.username = ? ORDER BY id_logiciels.computeur_id", username)
}

// SessionsDuGroupe rend les sessions des membres d'un groupe.
//
// Contrairement aux deux autres, cette vue part des MEMBRES : un membre sans
// session ouverte apparaît, avec des colonnes de session vides. C'est le sens
// de la commande — « qui, dans ce groupe, est connecté » se répond aussi par
// « personne ».
func SessionsDuGroupe(db *sql.DB, groupName string) ([]storage.UserConnected, error) {
	if injection := database.SanitizeIdentifier(groupName); injection != nil {
		return nil, injection
	}
	return lireSessions(db, `
		SELECT users.id_user, users.username, users.created_at,
		       user_sessions.key_time_validity, id_logiciels.computeur_id
		FROM users_group
		INNER JOIN users ON users_group.d_id_user = users.id_user
		INNER JOIN groups ON users_group.d_id_group = groups.id_group
		LEFT JOIN user_sessions ON user_sessions.d_id_user = users.id_user
		LEFT JOIN id_logiciels ON user_sessions.d_id_logiciel = id_logiciels.id_logiciel
		WHERE groups.group_name = ?
		ORDER BY users.username, id_logiciels.computeur_id`, groupName)
}

// lireSessions exécute une des requêtes ci-dessus et convertit les lignes.
func lireSessions(db *sql.DB, requete string, args ...any) ([]storage.UserConnected, error) {
	if db == nil {
		return nil, fmt.Errorf("base indisponible")
	}
	rows, err := db.Query(requete, args...)
	if err != nil {
		return nil, fmt.Errorf("lecture des sessions utilisateur : %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			logs.Write_Log("ERROR", "sessions utilisateur : fermeture du curseur : "+err.Error())
		}
	}()

	var out []storage.UserConnected
	for rows.Next() {
		var u storage.UserConnected
		// Colonnes NULLABLES : la vue par groupe montre aussi les membres SANS
		// session ouverte, dont les deux colonnes arrivent à NULL. Les lire
		// dans une chaîne Go faisait échouer le scan, donc toute la commande —
		// un seul membre déconnecté et le groupe entier devenait illisible.
		var validite, machine sql.NullString
		if err := rows.Scan(&u.ID, &u.Username, &u.CreatedAt, &validite, &machine); err != nil {
			return nil, fmt.Errorf("lecture des sessions utilisateur : %w", err)
		}
		u.TokenExpiry = validite.String
		u.Machine = machine.String
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("lecture des sessions utilisateur : %w", err)
	}
	return out, nil
}

// resoudreCompteEtMachine traduit les deux identifiants, et remonte ses erreurs.
//
// Les ignorer enverrait un 0 dans la requête : elle ne toucherait alors aucune
// ligne, et l'appelant croirait la session enregistrée ou fermée. C'est le
// défaut qui avait été corrigé dans DeleteDidLogin, et il n'y a aucune raison
// de le réintroduire ici.
func resoudreCompteEtMachine(db *sql.DB, username, computeurID string) (int, int, error) {
	if injection := database.SanitizeIdentifier(username, computeurID); injection != nil {
		return 0, 0, injection
	}
	idUser, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return 0, 0, fmt.Errorf("session : compte %s introuvable : %w", username, err)
	}
	idLogiciel, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return 0, 0, fmt.Errorf("session : machine %s introuvable : %w", computeurID, err)
	}
	return idUser, idLogiciel, nil
}
