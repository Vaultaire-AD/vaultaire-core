package webserveur

import (
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbuser "vaultaire/core/database/db-user"
	gc "vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	"vaultaire/core/web_serveur/session"
)

type ProfilPageData struct {
	User        storage.GetUserInfoSingle
	Keys        []storage.PublicKey
	HasWebAdmin bool

	// MustChangePassword réduit la page au seul formulaire de mot de passe.
	// La session est authentique, mais c'est la seule chose qu'elle autorise.
	MustChangePassword bool

	// PasswordWarning est le préavis affiché quand l'expiration approche.
	// Vide le reste du temps.
	PasswordWarning string

	// MFAEnabled et MFARequired pilotent l'encart « second facteur ».
	MFAEnabled  bool
	MFARequired bool
}

func ProfilHandler(w http.ResponseWriter, r *http.Request) {
	// ✅ Authentification
	//
	// allowPasswordChange = true : c'est LA page vers laquelle une session au mot
	// de passe expiré est renvoyée. La restreindre ici créerait une boucle de
	// redirection sur elle-même.
	username, sessionToken, ok := requireLogin(w, r, true)
	if !ok {
		return
	}
	mustChange := session.MustChangePassword(sessionToken)

	db := database.GetDatabase()
	userInfo, err := database.Command_GET_UserInfo(db, username)
	if err != nil {
		http.Error(w, "Erreur récupération infos utilisateur", 500)
		return
	}
	userid, err := database.Get_User_ID_By_Username(db, userInfo.Username)
	if err != nil {
		http.Error(w, "Erreur récupération ID utilisateur", 500)
		return
	}

	keys, err := dbuser.GetUserKeys(userid)
	if err != nil {
		logs.Write_Log("ERROR", "Erreur récupération clés publiques : "+err.Error())
		http.Error(w, "Erreur lors de la récupération des clés", http.StatusInternalServerError)
		return
	}

	// Determine if the current user has the web_admin permission
	hasAdmin := false
	if groupsID, action, err := permission.PrePermissionCheck(username, "web_admin"); err == nil {
		ok, _ := permission.CheckPermissionsMultipleDomains(groupsID, action, []string{"*"})
		hasAdmin = ok
	}

	data := ProfilPageData{
		User:               *userInfo,
		Keys:               keys,
		HasWebAdmin:        hasAdmin,
		MustChangePassword: mustChange,
	}
	data.PasswordWarning, data.MFAEnabled, data.MFARequired = profilAuthState(db, username)

	if r.Method == "GET" {
		tmpl, err := template.ParseFiles("web_packet/sso_WEB_page/templates/profil.html")
		if err != nil {
			http.Error(w, "Template manquant", 500)
			return
		}
		err = tmpl.Execute(w, data)
		if err != nil {
			logs.Write_Log("ERROR", "Erreur exécution template profil : "+err.Error())
			http.Error(w, "Erreur exécution template", 500)
		}
		return
	}

	// 🎯 Gestion POST (update user ou clés)
	action := r.FormValue("action")

	// MOT DE PASSE EXPIRÉ : une seule action reste possible.
	//
	// Le contrôle est ici, côté serveur, et pas seulement dans le rendu de la
	// page. Masquer les formulaires suffirait à un utilisateur ordinaire, mais
	// un POST forgé — ou un onglet resté ouvert avant l'expiration — atteindrait
	// « ajouter une clé publique » sur un compte dont le mot de passe n'est plus
	// valide. Or ajouter une clé publique, c'est se donner un accès SSH qui ne
	// dépend plus du mot de passe : exactement ce que l'expiration cherche à
	// interrompre.
	if mustChange && !(action == "update_info" && r.FormValue("password") != "") {
		logs.Write_Log("SECURITY", "profil: action « "+action+" » refusée pour "+
			username+" — mot de passe expiré, changement obligatoire")
		http.Error(w, "Votre mot de passe a expiré : changez-le avant toute autre action.",
			http.StatusForbidden)
		return
	}

	switch action {
	case "update_info":
		newUsername := r.FormValue("username")
		firstname := r.FormValue("firstname")
		lastname := r.FormValue("lastname")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm_password")
		currentPassword := r.FormValue("current_password")

		if password != "" && password != confirm {
			http.Error(w, "Mot de passe non confirmé", http.StatusBadRequest)
			return
		}

		currentUsername := username
		userID, err := database.Get_User_ID_By_Username(db, currentUsername)
		if err != nil {
			http.Error(w, "Utilisateur introuvable", http.StatusInternalServerError)
			return
		}

		// MOT DE PASSE ACTUEL EXIGÉ pour en changer.
		//
		// Il ne l'était pas. Combiné à l'absence d'invalidation des autres
		// sessions, un jeton volé — poste laissé ouvert, sauvegarde de
		// navigateur — permettait de changer le mot de passe sans connaître
		// l'ancien, et le propriétaire légitime ne pouvait plus reprendre la
		// main : changer son propre mot de passe n'évinçait pas l'intrus.
		if password != "" {
			storedHash, salt, err := database.Get_User_Password_By_ID(db, userID)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					"profil: lecture du mot de passe impossible pour "+currentUsername+" : "+err.Error())
				http.Error(w, "Erreur interne", http.StatusInternalServerError)
				return
			}
			if !gc.ComparePasswords(currentPassword, salt, storedHash) {
				logs.Write_Log("SECURITY",
					"profil: changement de mot de passe refusé pour "+currentUsername+" — mot de passe actuel incorrect")
				http.Error(w, "Mot de passe actuel incorrect", http.StatusForbidden)
				return
			}
		}

		err = database.Update_User_Info(db, userID, newUsername, firstname, lastname, password, "")
		if err != nil {
			http.Error(w, "Erreur mise à jour: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if newUsername != "" && newUsername != currentUsername {
			// Les sessions suivent le nouveau nom, puis un jeton neuf est émis.
			// Sans le report, les autres sessions pointeraient vers un compte
			// qui n'existe plus et échoueraient sur « utilisateur introuvable »
			// sans explication.
			session.RenameSessions(currentUsername, newUsername)
			currentUsername = newUsername

			newToken := session.CreateSession(newUsername)
			if newToken == "" {
				http.Error(w, "Session non renouvelée, reconnectez-vous", http.StatusInternalServerError)
				return
			}
			session.DeleteSession(sessionToken)
			setSessionCookie(w, newToken)
			sessionToken = newToken
		}

		if password != "" {
			// Toutes les AUTRES sessions sont fermées. La session courante est
			// conservée : déconnecter l'auteur du changement lui ferait croire
			// que l'opération a échoué.
			// La restriction est levée sur la session courante. Sans cette ligne,
			// l'utilisateur qui vient de changer son mot de passe expiré serait
			// renvoyé sur cette même page à la requête suivante — une boucle dont
			// il ne sortirait qu'en se reconnectant, en croyant que rien n'a été
			// enregistré.
			//
			// Les AUTRES sessions ne sont pas à corriger : elles sont fermées
			// juste en dessous.
			session.ClearMustChangePassword(sessionToken)

			if closed := session.DeleteOtherSessionsOf(currentUsername, sessionToken); closed > 0 {
				logs.Write_Log("INFO", fmt.Sprintf(
					"profil: mot de passe de %s changé, %d autre(s) session(s) fermée(s)",
					currentUsername, closed))
			} else {
				logs.Write_Log("INFO", "profil: mot de passe de "+currentUsername+" changé")
			}
		}

	case "delete_key":
		keyIDString := r.FormValue("key_id")
		keyID, err := strconv.Atoi(keyIDString)
		if err != nil {
			http.Error(w, "ID de clé invalide", http.StatusBadRequest)
			return
		}

		// Mettre dans un slice pour passer à la fonction
		err = dbuser.DeleteUserKeys([]int{keyID})
		if err != nil {
			logs.Write_Log("ERROR", "Erreur suppression clé : "+err.Error())
			http.Error(w, "Erreur suppression clé", http.StatusInternalServerError)
			return
		}

	case "add_key":
		file, header, err := r.FormFile("public_key_file")
		if err != nil {
			http.Error(w, "Erreur fichier clé", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Lire tout le contenu du fichier
		fileContent := make([]byte, header.Size)
		_, err = file.Read(fileContent)
		if err != nil {
			http.Error(w, "Impossible de lire le fichier", http.StatusInternalServerError)
			return
		}

		keyStr := strings.TrimSpace(string(fileContent))
		label := header.Filename

		// Vérifier que le contenu ressemble à une clé publique SSH
		if !strings.HasPrefix(keyStr, "ssh-rsa") && !strings.HasPrefix(keyStr, "ssh-ed25519") {
			http.Error(w, "Le fichier ne contient pas une clé publique valide", http.StatusBadRequest)
			return
		}

		// Ajouter la clé en base
		err = dbuser.AddUserKey(userid, keyStr, label)
		if err != nil {
			// Le message d'AddUserKey est déjà explicite : on ne le préfixe pas
			// une seconde fois. Le journal affichait « Erreur ajout clé
			// publique : Erreur ajout clé publique : Error 1062... ».
			logs.Write_Log("WARNING", "profil: ajout de clé refusé pour l'utilisateur "+
				strconv.Itoa(userid)+" : "+err.Error())
			// 409 et non 500 : une clé déjà enregistrée est un conflit, pas une
			// panne du serveur. Et le message part à l'utilisateur, sinon il
			// voit « Erreur lors de l'ajout » sans savoir quoi corriger.
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		logs.Write_Log("INFO", "Ajout d’une nouvelle clé publique : "+label)
	}

	http.Redirect(w, r, "/profil", http.StatusSeeOther)
}
