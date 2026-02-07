package webserveur

import (
	"vaultaire/serveur/database"
	dbuser "vaultaire/serveur/database/db-user"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/permission"
	"vaultaire/serveur/storage"
	"vaultaire/serveur/web_serveur/session"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ProfilPageData struct {
	User        storage.GetUserInfoSingle
	Keys        []storage.PublicKey
	HasWebAdmin bool
}

func ProfilHandler(w http.ResponseWriter, r *http.Request) {
	// ✅ Authentification
	tokenCookie, err := r.Cookie("session_token")
	if err != nil || tokenCookie.Value == "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	username, valid := session.ValidateToken(tokenCookie.Value)
	if !valid {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

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
		User:        *userInfo,
		Keys:        keys,
		HasWebAdmin: hasAdmin,
	}

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

	switch action {
	case "update_info":
		// même code qu'avant pour update profil
		newUsername := r.FormValue("username")
		firstname := r.FormValue("firstname")
		lastname := r.FormValue("lastname")
		password := r.FormValue("password")
		confirm := r.FormValue("confirm_password")

		if password != "" && password != confirm {
			http.Error(w, "Mot de passe non confirmé", 400)
			return
		}

		currentUsername, _ := session.ValidateToken(tokenCookie.Value)
		userID, err := database.Get_User_ID_By_Username(db, currentUsername)
		if err != nil {
			http.Error(w, "Utilisateur introuvable", 500)
			return
		}

		err = database.Update_User_Info(db, userID, newUsername, firstname, lastname, password, "")
		if err != nil {
			http.Error(w, "Erreur mise à jour: "+err.Error(), 500)
			return
		}

		if newUsername != currentUsername {
			newToken := session.CreateSession(newUsername)
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    newToken,
				HttpOnly: true,
				Secure:   true,
				Path:     "/",
				Expires:  time.Now().Add(30 * time.Minute),
			})
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
			logs.Write_Log("ERROR", "Erreur ajout clé publique : "+err.Error())
			http.Error(w, "Erreur lors de l'ajout de la clé", http.StatusInternalServerError)
			return
		}

		logs.Write_Log("INFO", "Ajout d’une nouvelle clé publique : "+label)
	}

	http.Redirect(w, r, "/profil", http.StatusSeeOther)
}
