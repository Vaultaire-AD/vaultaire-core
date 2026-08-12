package dbusers

import (
	"database/sql"
	"strconv"

	"vaultaire/core/global/security"
	"vaultaire/core/logs"
)

// VerifierMotDePasse contrôle le mot de passe d'un compte et réencode au besoin.
//
// # Pourquoi les quatre portes passent par ici
//
// Le portail web, le bind LDAP, les trames Ducky et le chemin PAM faisaient
// chacun la même séquence à la main : lire l'empreinte et le sel, appeler la
// comparaison, agir sur le booléen. Quatre copies d'une même décision.
//
// Le réencodage rend cette duplication coûteuse. Il ne peut avoir lieu qu'à
// l'instant d'une connexion réussie — c'est le seul moment où le mot de passe
// existe en clair — donc il doit être branché sur les QUATRE portes. Recopié
// quatre fois, il aurait été oublié quelque part, et les comptes qui se
// connectent par cette porte-là seraient restés en SHA-256 sans que rien ne le
// signale : la migration se serait arrêtée en silence, à moitié faite.
//
// Une seule fonction, et l'oubli devient impossible.
//
// # Le réencodage ne peut pas échouer bruyamment
//
// Le mot de passe est bon. Refuser la connexion parce que la base n'a pas voulu
// de l'écriture transformerait une amélioration d'empreinte en panne
// d'authentification. L'échec est donc journalisé et la connexion accordée : le
// compte gardera son empreinte héritée et sera repris à la prochaine occasion.
// # Pourquoi une erreur, et pas un simple faux
//
// Une panne de lecture de la base n'est pas un mauvais mot de passe. Les
// confondre a des conséquences concrètes : le chemin Ducky compte les échecs
// pour freiner les essais, et compter une indisponibilité de la base comme un
// échec ferait dégénérer une panne en freinage général de tous les comptes qui
// tentent de se connecter. L'appelant doit pouvoir distinguer les deux.
func VerifierMotDePasse(db *sql.DB, userID int, motDePasse string) (bool, error) {
	empreinte, sel, err := Get_User_Password_By_ID(db, userID)
	if err != nil {
		return false, err
	}

	valide, aReencoder := security.Verifier(motDePasse, sel, empreinte)
	if !valide {
		return false, nil
	}
	if aReencoder {
		reencoder(db, userID, motDePasse)
	}
	return true, nil
}

// reencoder remplace l'empreinte stockée par une empreinte argon2id neuve.
//
// password_changed_at n'est PAS touchée, et c'est le point délicat de cette
// fonction. Le mot de passe n'a pas changé : seule sa représentation change. La
// dater comme un changement repousserait l'expiration de tous les comptes du
// parc à leur première connexion après la bascule — une politique d'expiration
// annulée d'un coup, sans que personne ne l'ait décidé ni remarqué.
func reencoder(db *sql.DB, userID int, motDePasse string) {
	empreinte, selHex, err := security.Hacher(motDePasse)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"réencodage du mot de passe impossible (hachage) pour l'utilisateur "+strconv.Itoa(userID)+" : "+err.Error())
		return
	}

	_, err = db.Exec(`UPDATE users SET password = ?, salt = ? WHERE id_user = ?`,
		empreinte, selHex, userID)
	if err != nil {
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"réencodage du mot de passe impossible (écriture) pour l'utilisateur "+strconv.Itoa(userID)+" : "+err.Error())
		return
	}

	logs.Write_Log("INFO", "mot de passe réencodé en argon2id pour l'utilisateur "+strconv.Itoa(userID))
}
