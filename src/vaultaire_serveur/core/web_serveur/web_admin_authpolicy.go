package webserveur

import (
	"net/http"

	"vaultaire/core/database"
	dbauthpolicy "vaultaire/core/database/db_authpolicy"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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

	if r.Method == http.MethodPost {
		// Les groupes de l'appelant sont résolus même si l'action de cette page
		// n'exige aucune clé RBAC : les passer à vide ferait dépendre le
		// contrôle du fait qu'aucune clé ne soit déclarée, et le jour où l'une
		// serait ajoutée à cette action, elle serait vérifiée contre une liste
		// vide — donc toujours refusée, sans que la cause soit lisible.
		groupIDs, err := permission.GetGroupIDsForUser(username)
		if err != nil {
			logs.Write_Log("WARNING", "webadmin: groupes de "+username+" illisibles : "+err.Error())
		}

		// L'action passe par le registre : la validation des durées, la borne
		// haute et le message vivent dans authpolicy.set_password_policy.
		//
		// requireSuperadminPage ci-dessus reste en place et fait double emploi
		// avec ExigeSuperadmin de l'action. C'est délibéré : le premier protège
		// l'AFFICHAGE de la page, le second l'EXÉCUTION. Retirer l'un des deux
		// laisserait soit la page lisible par tous, soit l'action atteignable
		// par une requête forgée qui n'emprunterait pas ce handler.
		res, traite, err := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if err != nil {
				data.Error = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
			}
		}
	}

	// L'ancien corps analysait les durées, appelait SetPasswordPolicy et
	// composait les messages. Il ne vérifiait pas que le préavis soit plus court
	// que la validité : 90 jours d'avertissement pour 30 jours de validité était
	// accepté, et l'avertissement s'affichait alors en permanence. Le contrôle
	// est ajouté dans l'action.

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
