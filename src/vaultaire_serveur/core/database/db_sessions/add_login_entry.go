package dbsessions

import (
	"database/sql"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
)

func AddLoginEntry(db *sql.DB, userID int, sessionPublicKey []byte, clientSoftwareID string) {
	formattedTime := EcheanceSession()

	// La machine est résolue par le helper commun, et l'échec ARRÊTE la
	// fonction.
	//
	// get_id_logiciel, qui vivait ici, retournait une chaîne vide aussi bien
	// pour « machine inconnue » que pour « erreur de base ». Cette chaîne vide
	// partait ensuite dans un INSERT sur d_id_logiciel, une clé étrangère
	// entière : l'insertion échouait, l'échec n'était que journalisé, et
	// AddLoginEntry — qui ne retourne rien — laissait l'appelant croire la
	// session enregistrée. Une connexion réussie sans ligne did_login
	// correspondante, c'est une session que le nettoyage et le kill switch ne
	// retrouveront jamais.
	//
	// Continuer sans identifiant valide n'a aucun sens : on s'arrête, et on le
	// dit franchement dans le journal.
	logiciel_id, err := dbclients.Get_ClientID_By_ComputerID(db, clientSoftwareID)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: session non enregistrée, machine "+clientSoftwareID+" introuvable : "+err.Error())
		return
	}

	// INSERT … ON DUPLICATE KEY UPDATE, et non SELECT EXISTS puis INSERT.
	//
	// La séquence d'origine lisait puis écrivait sans verrou : deux
	// authentifications simultanées de la même paire (compte, machine) y
	// trouvaient toutes les deux « la ligne n'existe pas » et inséraient chacune
	// la leur. La machine apparaissait alors DEUX FOIS dans « status -c » — le
	// doublon que le point 92 a fermé pour les sessions PAM, par une autre porte.
	//
	// La fenêtre s'ouvre en fonctionnement normal : le « --fetch-key » de sshd
	// ouvre une session à chaque connexion SSH, en parallèle du tunnel.
	//
	// Depuis le TO-DO 107, la base porte l'unicité (uq_did_login) : c'est elle
	// qui tranche, et laisser MySQL le faire supprime la course au lieu de la
	// rendre plus rare.
	if _, err := db.Exec(`
		INSERT INTO did_login (d_id_user, session_key, key_time_validity, d_id_logiciel)
		VALUES (?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			session_key       = VALUES(session_key),
			key_time_validity = VALUES(key_time_validity)`,
		userID, sessionPublicKey, formattedTime, logiciel_id); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: enregistrement de la session échoué : "+err.Error())
		return
	}

	// users_logiciel : même remplacement, pour la même raison.
	//
	// Cette table porte la date de dernier usage d'un compte sur une machine.
	// Son unicité n'est pas garantie par la base ; on n'en pose pas ici, parce
	// qu'elle est lue ailleurs et qu'un doublon y est sans conséquence visible.
	// Mais la séquence lecture-puis-écriture, elle, n'a aucune raison de rester.
	var exists bool
	if err := db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM users_logiciel WHERE d_id_user = ? AND d_id_logiciel = ?)`,
		userID, logiciel_id).Scan(&exists); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: lecture de users_logiciel échouée : "+err.Error())
		return
	}

	if exists {
		if _, err := db.Exec(`
			UPDATE users_logiciel SET recent_utilisation = ?
			 WHERE d_id_user = ? AND d_id_logiciel = ?`,
			formattedTime, userID, logiciel_id); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"database: mise à jour de users_logiciel échouée : "+err.Error())
		}
		return
	}

	if _, err := db.Exec(`
		INSERT INTO users_logiciel (d_id_user, d_id_logiciel, recent_utilisation)
		VALUES (?, ?, ?)`,
		userID, logiciel_id, formattedTime); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeDBQuery,
			"database: insertion dans users_logiciel échouée : "+err.Error())
	}
}
