package webserveur

import (
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	dbusers "vaultaire/core/database/db_users"

	act "vaultaire/core/action"
	"vaultaire/core/database"

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
	userInfo, err := dbusers.Command_GET_UserInfo(db, username)
	if err != nil {
		http.Error(w, "Erreur récupération infos utilisateur", 500)
		return
	}
	userid, err := dbusers.Get_User_ID_By_Username(db, userInfo.Username)
	if err != nil {
		http.Error(w, "Erreur récupération ID utilisateur", 500)
		return
	}

	keys, err := dbusers.GetUserKeys(userid)
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
		tmpl, err := template.ParseFiles(CheminGabarit("profil.html"))
		if err != nil {
			http.Error(w, "Template manquant", 500)
			return
		}
		// Rendu en mémoire : un échec ici laisse la réponse intacte, donc
		// http.Error atteint réellement l'utilisateur au lieu de s'ajouter à une
		// page à moitié écrite. Cette page est la destination de toutes les
		// redirections de refus d'accès — tronquée, elle fait croire que c'est
		// la page d'origine qui est cassée.
		if err := rendreGabarit(w, tmpl, data); err != nil {
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
		userID, err := dbusers.Get_User_ID_By_Username(db, currentUsername)
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
			valide, err := dbusers.VerifierMotDePasse(db, userID, currentPassword)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeDBQuery,
					"profil: lecture du mot de passe impossible pour "+currentUsername+" : "+err.Error())
				http.Error(w, "Erreur interne", http.StatusInternalServerError)
				return
			}
			if !valide {
				logs.Write_Log("SECURITY",
					"profil: changement de mot de passe refusé pour "+currentUsername+" — mot de passe actuel incorrect")
				http.Error(w, "Mot de passe actuel incorrect", http.StatusForbidden)
				return
			}
		}

		err = dbusers.Update_User_Info(db, userID, newUsername, firstname, lastname, password, "")
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

		// LA CLÉ APPARTIENT-ELLE BIEN À CELUI QUI LA SUPPRIME ?
		//
		// DeleteUserKeys supprime par identifiant, sans regarder le
		// propriétaire. Cette page est ouverte à TOUT compte authentifié : sans
		// ce contrôle, n'importe qui pouvait retirer la clé SSH de n'importe
		// qui d'autre en postant un identifiant — un entier, donc facile à
		// parcourir. C'était un déni de service sur l'accès SSH du parc, à la
		// portée du premier compte venu.
		//
		// L'action user.remove_key portait déjà ce contrôle. Cette page ne
		// passe pas par le registre, et la garde n'avait pas été recopiée.
		cles, err := dbusers.GetUserKeys(userid)
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"profil: lecture des clés de "+username+" impossible : "+err.Error())
			http.Error(w, "Erreur suppression clé", http.StatusInternalServerError)
			return
		}

		// L'appartenance est portée par un BOOLÉEN, pas par le libellé.
		//
		// Déduire « trouvée » de « libellé non vide » confondrait deux cas
		// distincts : la clé d'un autre compte, et une clé du bon compte dont le
		// libellé est vide. Le libellé n'est obligatoire que depuis que l'ajout
		// passe par le registre ; les lignes antérieures peuvent en être
		// dépourvues, et leur propriétaire n'aurait plus aucun moyen de les
		// retirer — une clé SSH devenue indélébile par un contrôle de sécurité.
		appartient := false
		libelle := ""
		for _, k := range cles {
			if k.ID == keyID {
				appartient = true
				libelle = k.Label
				break
			}
		}
		if !appartient {
			logs.Write_LogCode("SECURITY", logs.CodeAuthPermission, fmt.Sprintf(
				"profil: %s a tenté de supprimer la clé %d, qui ne lui appartient pas",
				username, keyID))
			// 404 et non 403 : dire « elle ne vous appartient pas » confirmerait
			// que la clé existe, donc permettrait d'énumérer les identifiants.
			http.Error(w, "Clé introuvable", http.StatusNotFound)
			return
		}
		if libelle == "" {
			libelle = "sans libellé"
		}

		if err := dbusers.DeleteUserKeys([]int{keyID}); err != nil {
			logs.Write_LogCode("ERROR", logs.CodeDBQuery,
				"profil: suppression de la clé "+strconv.Itoa(keyID)+" de "+username+" : "+err.Error())
			http.Error(w, "Erreur suppression clé", http.StatusInternalServerError)
			return
		}

		// La suppression réussie n'était PAS journalisée : retirer une clé SSH
		// coupe un accès, et rien ne disait qui l'avait fait ni laquelle.
		logs.Write_Log("INFO", fmt.Sprintf(
			"profil: clé publique %q (id %d) retirée de %s", libelle, keyID, username))

	case "add_key":
		file, header, err := r.FormFile("public_key_file")
		if err != nil {
			http.Error(w, "Erreur fichier clé", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// io.ReadAll et non un unique file.Read.
		//
		// Read n'est pas tenu de remplir le tampon en une fois : il peut rendre
		// moins d'octets que demandé sans que ce soit une erreur. La clé arrivait
		// alors tronquée, donc inutilisable — et le contrôle de préfixe, lui,
		// passait, puisque c'est la FIN qui manquait.
		fileContent, err := io.ReadAll(file)
		if err != nil {
			http.Error(w, "Impossible de lire le fichier", http.StatusInternalServerError)
			return
		}

		keyStr := strings.TrimSpace(string(fileContent))
		label := header.Filename

		// Les MÊMES contrôles que « add -u <user> -k », et non une copie affaiblie.
		//
		// Cette page en avait sa propre version : deux types acceptés au lieu de
		// sept — une clé ECDSA ou matérielle était refusée ici et acceptée en
		// ligne de commande — et aucun contrôle du saut de ligne. Un fichier de
		// deux lignes ajoutait DEUX entrées à authorized_keys pour une seule
		// visible dans la liste : la seconde ne se serait jamais retirée par
		// l'interface.
		if err := act.ValiderCleSSH(keyStr); err != nil {
			logs.Write_Log("WARNING", "profil: clé refusée pour "+username+" : "+err.Error())
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Ajouter la clé en base
		err = dbusers.AddUserKey(userid, keyStr, label)
		if err != nil {
			// Le message d'AddUserKey est déjà explicite : on ne le préfixe pas
			// une seconde fois. Le journal affichait « Erreur ajout clé
			// publique : Erreur ajout clé publique : Error 1062... ».
			// Le NOM, et non l'identifiant numérique : « l'utilisateur 47 » oblige
			// à interroger la base pour lire son propre journal.
			logs.Write_Log("WARNING", "profil: ajout de clé refusé pour "+
				username+" : "+err.Error())
			// 409 et non 500 : une clé déjà enregistrée est un conflit, pas une
			// panne du serveur. Et le message part à l'utilisateur, sinon il
			// voit « Erreur lors de l'ajout » sans savoir quoi corriger.
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}

		// Le compte visé est nommé. La ligne disait « Ajout d'une nouvelle clé
		// publique : id_rsa.pub » — c'est-à-dire le nom du FICHIER déposé, et
		// rien d'autre. Or une clé publique donne un accès SSH sans mot de
		// passe : savoir sur QUEL compte elle a été posée est toute
		// l'information.
		logs.Write_Log("INFO", fmt.Sprintf(
			"profil: clé publique %q ajoutée à %s", label, username))
	}

	http.Redirect(w, r, "/profil", http.StatusSeeOther)
}
