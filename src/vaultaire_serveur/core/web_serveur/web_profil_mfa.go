package webserveur

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"
	"time"
	dbusers "vaultaire/core/database/db_users"

	"vaultaire/core/auth/passwordpolicy"
	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	gc "vaultaire/core/global/security"
	"vaultaire/core/global/security/qrcode"
	"vaultaire/core/global/security/totp"
	"vaultaire/core/logs"
)

// Enrôlement du second facteur, côté utilisateur.
//
// L'enrôlement se fait EN DEUX TEMPS, et c'est le point structurant de ce
// fichier : le secret est d'abord enregistré sans être actif, puis activé
// seulement après que l'utilisateur a produit un code valide. Écrire secret et
// activation d'un seul geste enfermerait dehors quiconque ferme l'onglet entre
// l'affichage du QR code et sa lecture par le téléphone — et il faudrait alors
// un administrateur pour le débloquer, sur une manipulation que l'utilisateur
// vient d'initier lui-même.

// mfaIssuer est le nom affiché dans l'application d'authentification.
const mfaIssuer = "Vaultaire"

// MFAEnrollData alimente la page d'enrôlement.
type MFAEnrollData struct {
	Username string

	// Enabled : un second facteur est déjà actif. La page bascule alors en
	// affichage d'état, sans secret.
	Enabled bool

	// Required : un groupe impose le second facteur. L'encart devient un
	// passage obligé plutôt qu'une proposition.
	Required bool

	// SecretDisplay est le secret en groupes de quatre, pour la saisie manuelle
	// quand la caméra ne lit pas le code.
	SecretDisplay string

	// OtpauthURI est l'URL d'enrôlement, affichée en clair et cliquable.
	OtpauthURI string

	// QRCode est le rendu SVG de cette URL.
	//
	// Il est calculé PAR LE SERVEUR, avec core/global/security/qrcode. Le faire
	// dessiner par une bibliothèque JavaScript servie depuis un CDN reviendrait
	// à envoyer le secret TOTP du compte à un tiers ; le faire dessiner par une
	// dépendance Go ajouterait du code non audité sur le chemin d'un secret
	// d'authentification. L'encodeur maison ne fait que du mode octet, niveau M,
	// versions 1 à 10 : c'est tout ce qu'une URI otpauth demande.
	//
	// template.HTML : le SVG est inséré tel quel. Il est produit ici, jamais reçu
	// de l'extérieur, et son seul champ variable est échappé à la génération.
	QRCode template.HTML

	Error   string
	Success string
}

// withEnrollmentSecret remplit les trois représentations du secret : la clé à
// recopier, l'URI et le QR code. Les trois viennent du MÊME secret relu en base,
// pour qu'aucune ne puisse diverger des autres.
func withEnrollmentSecret(data MFAEnrollData, username, secret string) MFAEnrollData {
	data.SecretDisplay = totp.FormatSecretForDisplay(secret)
	data.OtpauthURI = totp.ProvisioningURI(mfaIssuer, username, secret)

	svg, err := qrcode.EncodeSVG(data.OtpauthURI, 5, "Code d'enrôlement du second facteur")
	if err != nil {
		// L'enrôlement reste possible à la main : la clé et le lien sont
		// affichés. On journalise sans interrompre — perdre le QR code est une
		// gêne, pas un motif de refuser l'activation du second facteur.
		logs.Write_LogCode("WARNING", logs.CodeNone,
			"profil: QR code d'enrôlement non généré pour "+username+" : "+err.Error())
		return data
	}
	data.QRCode = template.HTML(svg)
	return data
}

// ProfilMFAHandler affiche et traite l'enrôlement du second facteur.
func ProfilMFAHandler(w http.ResponseWriter, r *http.Request) {
	// allowPasswordChange = false : un mot de passe expiré renvoie vers /profil.
	// Enrôler un second facteur sur un compte dont le mot de passe n'est plus
	// valide n'aurait pas de sens — le premier facteur doit être sain avant qu'on
	// en ajoute un second.
	username, _, ok := requireLogin(w, r, false)
	if !ok {
		return
	}

	db := database.GetDatabase()
	state, err := dbauthpolicy.GetAuthState(db, username)
	if err != nil {
		http.Error(w, "Erreur lecture du compte", http.StatusInternalServerError)
		return
	}
	required, _ := dbauthpolicy.IsMFARequired(db, username)

	data := MFAEnrollData{Username: username, Enabled: state.MFAEnabled, Required: required}

	switch {
	case r.Method != http.MethodPost:
		renderMFAEnroll(w, prepareEnrollment(db, username, data))

	case r.FormValue("action") == "start":
		if state.MFAEnabled {
			data.Error = "Un second facteur est déjà actif."
			renderMFAEnroll(w, data)
			return
		}
		secret, err := totp.GenerateSecret()
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeNone, "profil: génération du secret MFA impossible : "+err.Error())
			data.Error = "Impossible de générer un secret, réessayez."
			renderMFAEnroll(w, data)
			return
		}
		if err := dbauthpolicy.StartMFAEnrollment(db, username, secret); err != nil {
			data.Error = err.Error()
			renderMFAEnroll(w, data)
			return
		}
		renderMFAEnroll(w, withEnrollmentSecret(data, username, secret))

	case r.FormValue("action") == "confirm":
		// Le secret est relu en base et jamais repris d'un champ caché du
		// formulaire. Un secret transmis par le client serait un secret CHOISI par
		// le client : n'importe qui pourrait activer un second facteur dont il
		// connaît la graine sur un compte qu'il vient de compromettre, et le
		// verrouiller ainsi contre son propriétaire légitime.
		fresh, err := dbauthpolicy.GetAuthState(db, username)
		if err != nil || fresh.MFASecret == "" {
			data.Error = "Aucun enrôlement en cours. Recommencez."
			renderMFAEnroll(w, data)
			return
		}
		counter, valid := totp.Validate(fresh.MFASecret, r.FormValue("code"), time.Now())
		if !valid {
			data.Error = "Code invalide. Vérifiez l'heure de votre téléphone."
			renderMFAEnroll(w, withEnrollmentSecret(data, username, fresh.MFASecret))
			return
		}
		if err := dbauthpolicy.ActivateMFA(db, username, counter); err != nil {
			data.Error = err.Error()
			renderMFAEnroll(w, data)
			return
		}
		data.Enabled = true
		data.Success = "Second facteur activé."
		renderMFAEnroll(w, data)

	case r.FormValue("action") == "disable":
		// Se retirer soi-même son second facteur suppose de prouver son mot de
		// passe. Sans cette preuve, un jeton de session volé — poste laissé
		// ouvert — suffirait à désactiver la protection puis à revenir plus tard
		// avec le seul mot de passe : le second facteur serait contournable par
		// la chose contre laquelle il protège.
		if !confirmOwnPassword(db, username, r.FormValue("current_password")) {
			logs.Write_Log("SECURITY", "profil: désactivation MFA refusée pour "+username+" — mot de passe incorrect")
			data.Error = "Mot de passe incorrect."
			renderMFAEnroll(w, data)
			return
		}
		if required {
			// Un groupe l'impose : le retrait est refusé, sinon l'exigence ne
			// serait qu'une suggestion.
			data.Error = "Votre groupe impose le second facteur : il ne peut pas être désactivé."
			renderMFAEnroll(w, data)
			return
		}
		if err := dbauthpolicy.ResetMFA(db, username, username); err != nil {
			data.Error = err.Error()
			renderMFAEnroll(w, data)
			return
		}
		data.Enabled = false
		data.Success = "Second facteur désactivé."
		renderMFAEnroll(w, data)

	default:
		http.Redirect(w, r, "/profil/mfa", http.StatusSeeOther)
	}
}

// prepareEnrollment relance un enrôlement interrompu.
//
// Si un secret existe sans être actif, l'utilisateur a quitté la page entre les
// deux étapes. On lui réaffiche le MÊME secret plutôt que d'en tirer un nouveau :
// il l'a peut-être déjà enregistré dans son téléphone, et lui en donner un autre
// invaliderait silencieusement l'entrée qu'il vient de créer.
func prepareEnrollment(db *sql.DB, username string, data MFAEnrollData) MFAEnrollData {
	if data.Enabled {
		return data
	}
	state, err := dbauthpolicy.GetAuthState(db, username)
	if err != nil || state.MFASecret == "" {
		return data
	}
	return withEnrollmentSecret(data, username, state.MFASecret)
}

// confirmOwnPassword vérifie le mot de passe du compte courant.
func confirmOwnPassword(db *sql.DB, username, password string) bool {
	if password == "" {
		return false
	}
	userID, err := dbusers.Get_User_ID_By_Username(db, username)
	if err != nil {
		return false
	}
	hash, salt, err := dbusers.Get_User_Password_By_ID(db, userID)
	if err != nil {
		return false
	}
	return gc.ComparePasswords(password, salt, hash)
}

// renderMFAEnroll affiche la page d'enrôlement.
func renderMFAEnroll(w http.ResponseWriter, data MFAEnrollData) {
	tmpl, err := template.ParseFiles(adminTplDir + "/profil_mfa.html")
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "profil: template MFA illisible : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "profil: rendu MFA échoué : "+err.Error())
	}
}

// profilAuthState résume l'état d'authentification pour la page profil.
//
// Retourne le texte de préavis — vide hors de la fenêtre d'avertissement —, si
// le second facteur est actif, et s'il est exigé.
//
// LE PRÉAVIS EST CALCULÉ ICI ET PAS DANS LE TEMPLATE. Un template qui compare
// des dates finit par contenir de la logique métier que rien ne teste, et qui
// diverge de celle du serveur : l'interface annoncerait « 3 jours » quand LDAP
// refuse déjà.
func profilAuthState(db *sql.DB, username string) (warning string, mfaEnabled, mfaRequired bool) {
	if state, err := dbauthpolicy.GetAuthState(db, username); err == nil {
		mfaEnabled = state.MFAEnabled && state.MFASecret != ""

		if status := passwordpolicy.CheckFromState(db, state); status.ShouldWarn() {
			switch status.DaysUntilExpiry {
			case 1:
				warning = "Votre mot de passe expire demain."
			default:
				warning = "Votre mot de passe expire dans " +
					plural(status.DaysUntilExpiry, "jour") + "."
			}
		}
	}
	mfaRequired, _ = dbauthpolicy.IsMFARequired(db, username)
	return warning, mfaEnabled, mfaRequired
}

// plural écrit « 3 jours » ou « 1 jour ».
func plural(n int, word string) string {
	s := strconv.Itoa(n) + " " + word
	if n > 1 {
		s += "s"
	}
	return s
}
