package dbschema

import (
	"database/sql"
	"fmt"
	"log"
	"time"
	"vaultaire/core/auth/passwordpolicy"
	database "vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// CreateDefaultAdminUser crée l'utilisateur administrateur par défaut s'il n'existe pas, et l'ajoute au groupe vaultaire.
// Si l'admin existe déjà (ex: redémarrage du conteneur), la création est ignorée et le processus continue.
func CreateDefaultAdminUser(db *sql.DB) {
	logs.Write_Log("INFO", "bootstrap: checking default administrator")

	if storage.Administrateur_Username == "" {
		logs.Write_LogCode("CRITICAL", logs.CodeInternal, "bootstrap: administrator username is empty")
		log.Fatal("bootstrap: administrator username is empty")
	}
	if storage.Administrateur_Password == "" {
		logs.Write_LogCode("CRITICAL", logs.CodeInternal, "bootstrap: administrator password is empty")
		log.Fatal("bootstrap: administrator password is empty")
	}

	userID, err := dbusers.Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err == nil {
		logs.Write_Log("INFO", fmt.Sprintf("bootstrap: administrator '%s' already exists (id=%d)", storage.Administrateur_Username, userID))
		_, _ = db.Exec(`
			INSERT IGNORE INTO users_group (d_id_user, d_id_group)
			SELECT ?, g.id_group FROM groups g WHERE g.group_name = 'vaultaire'
		`, userID)
		logs.Write_Log("INFO", "bootstrap: starting with existing administrator")
		return
	}

	logs.Write_Log("INFO", "bootstrap: creating new administrator")

	// argon2id dès l'amorçage, comme partout ailleurs.
	//
	// Ce compte-ci a une raison de plus de ne pas naître en SHA-256 : c'est le
	// SEUL qui existe au premier démarrage, il porte l'accès total, et son mot de
	// passe vient d'un fichier de configuration — donc, sur une installation qui
	// n'a pas changé les valeurs de démonstration, d'une chaîne connue de tous.
	// Le laisser en SHA-256 en attendant sa première connexion aurait offert la
	// cible la plus intéressante de la base dans le format le plus faible.
	//
	// PreparerNouveauMotDePasse et non security.Hacher : le compte d'amorçage est
	// celui qui porte l'accès total, il serait absurde qu'il soit le seul dispensé
	// de la règle de robustesse (TO-DO 100). Sans base lisible, la politique
	// retombe sur son plancher — donc ici, on durcit.
	hashHex, saltHex, err := passwordpolicy.PreparerNouveauMotDePasse(
		db, storage.Administrateur_Username, storage.Administrateur_Password)
	if err != nil {
		// Le message dit QUOI FAIRE, et sur trois lignes : celui qui le lit est
		// devant un serveur qui ne démarre pas, au premier démarrage, et il n'a
		// aucun autre moyen d'apprendre que le mot de passe d'amorçage est refusé.
		logs.Write_LogCode("CRITICAL", logs.CodeInternal,
			"bootstrap: mot de passe administrateur refusé : "+err.Error())
		log.Fatalf("bootstrap: le mot de passe du compte d'amorçage est refusé.\n"+
			"  %v\n"+
			"  Corrigez « administrateur.password » dans serveur_conf.yaml, ou posez\n"+
			"  VAULTAIRE_ADMIN_PASSWORD, puis redémarrez. Ce compte porte l'accès\n"+
			"  total : il ne peut pas être le seul dispensé de la règle.", err)
	}

	firstname := "Admin"
	lastname := "System"
	email := storage.Administrateur_Username + "@vaultaire.local"
	birthdate := "01/01/3300"

	err = dbusers.Create_New_User(
		database.GetDatabase(),
		storage.Administrateur_Username,
		firstname,
		lastname,
		email,
		hashHex,
		saltHex,
		birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: administrator creation failed: "+err.Error())
		log.Fatalf("bootstrap: administrator creation failed: %v", err)
	}
	logs.Write_Log("INFO", "bootstrap: administrator user created")

	userID, err = dbusers.Get_User_ID_By_Username(db, storage.Administrateur_Username)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: failed to retrieve administrator ID: "+err.Error())
		log.Fatalf("bootstrap: failed to retrieve administrator ID: %v", err)
	}

	// 6. Ajouter la clé publique si fournie
	if storage.Administrateur_PublicKey != "" {
		_, err = db.Exec(`
			INSERT IGNORE INTO user_public_keys (id_user, public_key, label)
			VALUES (?, ?, 'Admin Key')
		`,
			userID,
			storage.Administrateur_PublicKey,
		)
		if err != nil {
			logs.Write_LogCode("WARNING", logs.CodeDBQuery, "bootstrap: failed to add public key: "+err.Error())
		} else {
			logs.Write_Log("INFO", "bootstrap: public key added")
		}
	}

	_, err = db.Exec(`
		INSERT IGNORE INTO users_group (d_id_user, d_id_group)
		SELECT ?, g.id_group
		FROM groups g
		WHERE g.group_name = 'vaultaire'
	`,
		userID,
	)
	if err != nil {
		logs.Write_LogCode("CRITICAL", logs.CodeDBQuery, "bootstrap: failed to add administrator to vaultaire group: "+err.Error())
		log.Fatalf("bootstrap: failed to add administrator to vaultaire group: %v", err)
	}

	// LE MOT DE PASSE D'AMORÇAGE EST PROVISOIRE — TO-DO 99.
	//
	// Ce compte entre dans le groupe `vaultaire` : tous les droits, sur tous les
	// domaines. Son mot de passe vient d'un fichier de configuration, donc il est
	// connu d'au moins une autre personne que son titulaire — et, sur une
	// installation faite depuis un modèle, de tous ceux qui ont lu ce modèle.
	//
	// SANS ÉCHÉANCE, contrairement aux autres mots de passe provisoires.
	// L'échéance fait cesser de fonctionner un mot de passe qu'on n'a pas
	// remplacé à temps ; l'appliquer ICI condamnerait une installation dont
	// personne ne s'est occupé pendant deux jours — sans laisser de recours,
	// puisque ce compte EST le recours. Le changement reste obligatoire, il
	// n'est simplement pas daté.
	//
	// Non bloquant, mais en SECURITY : le compte existe, le refaire échouerait,
	// et un superadmin dont le mot de passe n'est pas marqué à changer est
	// exactement ce que ce point corrige.
	if err := passwordpolicy.MarquerProvisoire(db, storage.Administrateur_Username, 0); err != nil {
		logs.Write_Log("SECURITY", fmt.Sprintf(
			"bootstrap: le compte %s a été créé mais son mot de passe n'a pas pu être "+
				"marqué « à changer » (%v) — changez-le sur le portail dès la première "+
				"connexion", storage.Administrateur_Username, err))
	}

	logs.Write_Log("INFO", fmt.Sprintf(
		"bootstrap: administrator '%s' created and added to vaultaire group — "+
			"son mot de passe est PROVISOIRE, à changer sur le portail",
		storage.Administrateur_Username))
}
