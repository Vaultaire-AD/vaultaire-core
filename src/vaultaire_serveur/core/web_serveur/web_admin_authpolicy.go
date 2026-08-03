package webserveur

import (
	"net/http"
	"strconv"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Page de la politique d'authentification — /admin/authpolicy.
//
// ACCÈS RÉSERVÉ AU GROUPE `vaultaire`, comme les restrictions GPO et pour la
// même raison : ce réglage ne porte pas sur une entité d'un domaine, il décide
// du jour où l'ensemble de l'annuaire cesse d'accepter ses mots de passe. Une
// clé RBAC déléguée par domaine n'aurait pas de sens sur un réglage qui n'a pas
// de domaine, et en faire une action globale de plus reviendrait à dire que le
// délégué d'un domaine peut verrouiller tous les autres.

// authPolicyView alimente la page.
type authPolicyView struct {
	Username  string
	DnsEnable bool
	Section   string
	Message   string
	Error     string

	MaxAgeDays int
	WarnDays   int
	Enabled    bool

	// MaxAgeLimit et WarnLimit sont affichés dans le formulaire pour que les
	// bornes soient visibles avant la saisie, et non découvertes par un refus.
	MaxAgeLimit int
	WarnLimit   int
}

// Bornes reprises de la couche base. Recopiées ici pour l'affichage seulement :
// la validation qui compte est celle de SetPasswordPolicy, côté base, qui
// s'applique aussi à une requête forgée.
const (
	authPolicyMaxAgeLimit = 3650
	authPolicyWarnLimit   = 365
)

// AdminAuthPolicyHandler affiche et enregistre la politique de mot de passe.
func AdminAuthPolicyHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireSuperadminPage(w, r)
	if !ok {
		return
	}
	db := database.GetDatabase()

	data := authPolicyView{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "authpolicy",
		MaxAgeLimit: authPolicyMaxAgeLimit, WarnLimit: authPolicyWarnLimit,
	}

	if r.Method == http.MethodPost && r.FormValue("action") == "save_password_policy" {
		maxAge, errAge := strconv.Atoi(r.FormValue("max_age_days"))
		warn, errWarn := strconv.Atoi(r.FormValue("warn_days"))

		switch {
		case errAge != nil || errWarn != nil:
			data.Error = "Les deux durées doivent être des nombres entiers de jours."
		default:
			policy := dbauthpolicy.PasswordPolicySettings{MaxAgeDays: maxAge, WarnDays: warn}
			if err := dbauthpolicy.SetPasswordPolicy(db, policy, username); err != nil {
				data.Error = err.Error()
			} else if policy.Enabled() {
				// Le message dit ce qui va se passer aux comptes anciens. Activer
				// une politique à 90 jours sur un annuaire qui n'en avait aucune
				// expire d'un coup tout ce qui n'a pas été changé depuis trois
				// mois : c'est le comportement correct, mais il ne doit pas être
				// une surprise.
				data.Message = "Politique enregistrée. Les comptes dont le mot de passe " +
					"date de plus de " + strconv.Itoa(policy.MaxAgeDays) + " jours sont expirés dès maintenant."
			} else {
				data.Message = "Expiration désactivée."
			}
			logs.Write_Log("INFO", "webadmin: politique de mot de passe enregistrée par "+username)
		}
	}

	// Relu après l'action : le formulaire doit montrer ce qui est réellement en
	// base, pas ce qui vient d'être posté. Une valeur ramenée dans ses bornes par
	// la lecture serait sinon réaffichée telle que saisie, et l'administrateur
	// croirait avoir enregistré autre chose.
	current := dbauthpolicy.GetPasswordPolicy(db)
	data.MaxAgeDays, data.WarnDays, data.Enabled = current.MaxAgeDays, current.WarnDays, current.Enabled()

	if err := executeAdminPage(w, "admin_authpolicy.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
