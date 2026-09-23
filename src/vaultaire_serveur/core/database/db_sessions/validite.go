package dbsessions

import (
	"database/sql"
	"fmt"
	"time"

	dbclients "vaultaire/core/database/db_clients"
)

// Durée de vie d'une ligne `did_login`, et prolongation par le battement.
//
// # Une constante, parce qu'il y en avait trois
//
// `10 * time.Minute` était écrit dans AddLoginEntry, RafraichirConnexion et
// RefreshSessionValidity. Trois copies d'un même nombre, dans trois fichiers
// qu'on ne modifie jamais ensemble : allonger la validité d'un côté aurait
// donné des sessions qui expirent ou non selon le chemin qui les a écrites,
// c'est-à-dire un comportement qu'on ne peut pas expliquer en lisant un seul
// fichier.
//
// # Pourquoi dix minutes, et pas plus
//
// C'est une SURVIE SANS NOUVELLE, pas une durée de session. Une machine qui
// bat toutes les deux minutes (`server_check_online_minutes`) repousse
// l'échéance bien avant qu'elle n'arrive ; dix minutes, c'est ce qu'on accepte
// d'afficher comme « connecté » une machine qui, en réalité, a été débranchée.
const ValiditeSession = 10 * time.Minute

// EcheanceSession rend l'horodatage d'expiration à écrire en base.
//
// Le format est celui des trois fonctions d'origine : MySQL l'accepte pour un
// TIMESTAMP, et le changer ferait échouer des écritures sans rien apporter.
func EcheanceSession() string {
	return time.Now().Add(ValiditeSession).Format("2006/01/02 15:04:05")
}

// ProlongerSessionsDeLaMachine repousse l'échéance de TOUTES les lignes
// `did_login` d'une machine — la sienne comme celles de ses utilisateurs.
//
// # Pourquoi les sessions utilisateur n'ont pas de battement à elles
//
// Une session ouverte par PAM n'a ni connexion ni clé propre : elle vit dans le
// tunnel de la machine (voir la trame 03_01). Rien ne peut donc la prolonger de
// lui-même, et une session PAM enregistrée telle quelle disparaîtrait de
// `status -u` au bout de dix minutes, alors que la personne est toujours
// devant son écran.
//
// Le battement de la machine est la seule preuve d'existence disponible, et
// c'est la bonne : si la machine s'éteint, ses sessions utilisateur n'ont plus
// lieu d'être, et elles expirent avec elle.
//
// # Ce que cela n'attrape pas, assumé
//
// Une déconnexion dont la trame de fin (03_11) se perd laisse la ligne vivante
// tant que la machine bat. C'est le prix de ce choix : l'alternative — faire
// expirer les sessions utilisateur malgré le battement — afficherait toutes les
// personnes réellement connectées comme déconnectées au bout de dix minutes,
// ce qui est un mensonge bien plus fréquent.
func ProlongerSessionsDeLaMachine(db *sql.DB, computeurID string) (int64, error) {
	if db == nil {
		return 0, fmt.Errorf("base indisponible")
	}
	idLogiciel, err := dbclients.Get_ClientID_By_ComputerID(db, computeurID)
	if err != nil {
		return 0, fmt.Errorf("prolongation des sessions : machine %s introuvable : %w", computeurID, err)
	}

	res, err := db.Exec(
		"UPDATE did_login SET key_time_validity = ? WHERE d_id_logiciel = ?",
		EcheanceSession(), idLogiciel)
	if err != nil {
		return 0, fmt.Errorf("prolongation des sessions de %s : %w", computeurID, err)
	}

	// Zéro ligne n'est PAS une erreur : une machine qui bat sans qu'aucune
	// session ne soit ouverte est le cas le plus courant du parc.
	n, err := res.RowsAffected()
	if err != nil {
		return 0, nil
	}
	return n, nil
}
