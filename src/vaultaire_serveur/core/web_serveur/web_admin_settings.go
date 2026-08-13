package webserveur

import (
	"net/http"
	"strconv"

	act "vaultaire/core/action"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/reglages"
	"vaultaire/core/storage"
)

// Page des durées d'exploitation.
//
// # Accès : web_admin ET read:log pour voir, write:server pour changer
//
// La lecture emprunte `read:log` — les deux répondent à « puis-je regarder
// comment ce serveur est réglé ». L'écriture exige `write:server`, la même clé
// que le mode debug et la purge des sessions.
//
// Les deux droits sont exigés SÉPARÉMENT, et le bouton n'apparaît pas sans le
// second. Une page qui montrerait des champs modifiables refusés à la
// soumission ferait perdre du temps et ne dirait pas lequel manque.
//
// La décision reste portée par les ACTIONS : cette page ne lit ni n'écrit la
// base directement. C'est ce qui a manqué à la page des certificats, où le
// contrôle ne tenait qu'à un `if` de la page — voir AdminCertificatesHandler.

type reglageVue struct {
	reglages.Etat
	// Modifiable dit si l'appelant peut changer CE réglage. Porté par ligne
	// plutôt que par page : le gabarit n'a pas à refaire le raisonnement.
	Modifiable bool
}

func AdminSettingsHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	if !checkWebAdminRBAC(w, r, groupIDs, permission.ActionReadLog) {
		return
	}

	appelant := act.Appelant{Username: username, GroupIDs: groupIDs}
	peutEcrire := permission.HasActionAnywhere(groupIDs, permission.ActionWriteServer)

	data := struct {
		Username   string
		DnsEnable  bool
		Section    string
		Message    string
		Error      string
		Reglages   []reglageVue
		PeutEcrire bool
	}{
		Username: username, DnsEnable: storage.Dns_Enable,
		Section: "settings", PeutEcrire: peutEcrire,
	}

	if r.Method == http.MethodPost {
		data.Message, data.Error = traiterReglage(r, appelant, username)
	}

	// L'état est relu APRÈS l'écriture, pour que la page montre la base et non
	// la valeur qu'on croit avoir posée.
	res, err := act.Executer("settings.list", appelant, act.Params{})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebAdmin, "webadmin: settings list failed: "+err.Error())
		http.Error(w, "Erreur lecture des réglages", http.StatusInternalServerError)
		return
	}
	etats, _ := res.Donnees.([]reglages.Etat)
	for _, e := range etats {
		data.Reglages = append(data.Reglages, reglageVue{Etat: e, Modifiable: peutEcrire})
	}

	if err := executeAdminPage(w, "admin_settings.html", data); err != nil {
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}

// traiterReglage applique une soumission et rend (message, erreur).
//
// L'action est nommée par le formulaire et traduite par le pont, comme partout
// ailleurs : la page ne choisit pas quelle action appeler à partir des champs
// reçus, sans quoi un champ ajouté au gabarit ouvrirait un chemin que personne
// n'a déclaré.
func traiterReglage(r *http.Request, appelant act.Appelant, username string) (message, erreur string) {
	if err := r.ParseForm(); err != nil {
		return "", "Formulaire illisible."
	}

	cle := r.PostFormValue("setting")
	if cle == "" {
		return "", "Aucun réglage désigné."
	}

	nom := "settings.set"
	p := act.Params{"setting": cle, "value": r.PostFormValue("value")}
	if r.PostFormValue("action") == "reset_setting" {
		nom = "settings.reset"
		p = act.Params{"setting": cle}
	}

	res, err := act.Executer(nom, appelant, p)
	if err != nil {
		return "", MessageDActionPourAffichage(res, err)
	}
	return res.Message, ""
}

// bornesLisibles rend « entre 1 et 60 min », pour l'attribut de saisie.
//
// Exportée au gabarit par la vue plutôt que recomposée en HTML : les bornes
// viennent du catalogue Go, et les recopier dans le gabarit les ferait diverger
// au premier ajustement.
func (v reglageVue) BornesLisibles() string {
	return "entre " + strconv.Itoa(v.Min) + " et " + strconv.Itoa(v.Max) + " " + string(v.Unite)
}
