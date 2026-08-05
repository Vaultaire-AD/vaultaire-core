package webserveur

// Page d'administration des clés d'enrôlement des clients service.
//
// # Le secret n'est affiché qu'une fois, et jamais deux
//
// La clé émise est rendue dans la réponse au POST qui l'a créée, puis oubliée :
// seul son condensat part en base. Recharger la page ne la remontre pas, et
// aucune route ne permet de la relire. C'est la même règle que le CLI, et c'est
// ce qui rend le vol de la base sans intérêt pour un attaquant.

import (
	"database/sql"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// enrollKeyView décore une clé pour l'affichage.
type enrollKeyView struct {
	dbenrollment.Record
	Status      string
	Uses        string
	ExpiresText string
	CreatedText string
	Consumers   []dbenrollment.Use
}

type enrollView struct {
	Username  string
	DnsEnable bool
	Section   string
	Message   string
	Error     string

	// Secret n'est renseigné qu'immédiatement après une émission.
	Secret     string
	SecretType string

	Keys  []enrollKeyView
	Types []clienttype.Definition

	// CanCreate : le droit d'émettre une clé ordinaire.
	// IsSuperadmin : celui d'en émettre une pour un type qui peut agir au nom
	// d'un utilisateur.
	CanCreate    bool
	IsSuperadmin bool

	Detail *enrollKeyView
}

// AdminEnrollHandler affiche et traite les clés d'enrôlement.
func AdminEnrollHandler(w http.ResponseWriter, r *http.Request) {
	username, groupIDs, ok := requireWebAdminWithGroupIDs(w, r)
	if !ok {
		return
	}
	db := database.GetDatabase()

	// Même clé RBAC que le CLI, et exigée sur « * » : une clé d'enrôlement
	// n'appartient à aucun domaine, le service qu'elle fera naître parle au
	// cluster entier.
	if !checkWebAdminRBAC(w, r, groupIDs, "read:get:client") {
		return
	}
	canCreate, _ := checkWebAdminRBACOnDomains(groupIDs, "write:create:client", []string{"*"})

	data := enrollView{
		Username: username, DnsEnable: storage.Dns_Enable, Section: "enroll",
		Types:        clienttype.All(),
		CanCreate:    canCreate,
		IsSuperadmin: isprotected.IsSuperadmin(db, username),
	}

	if r.Method == http.MethodPost {
		switch r.FormValue("action") {
		case "create_key":
			data.Secret, data.SecretType, data.Message, data.Error =
				createEnrollmentKey(r, username, canCreate, data.IsSuperadmin)
		case "revoke_key":
			data.Message, data.Error = revokeEnrollmentKey(r, username, canCreate)
		}
	}

	keys, err := dbenrollment.ListKeys(db)
	if err != nil {
		data.Error = "Lecture des clés impossible : " + err.Error()
	}
	now := time.Now()
	for _, k := range keys {
		data.Keys = append(data.Keys, decorateKey(k, now))
	}

	// Détail : les services entrés par une clé. Sans cette vue, la question
	// « qu'est-ce qui est entré avec cette clé ? » n'a pas de réponse le jour où
	// l'on découvre qu'elle a fuité.
	if idStr := r.URL.Query().Get("key"); idStr != "" {
		if id, err := strconv.Atoi(idStr); err == nil {
			for i := range data.Keys {
				if data.Keys[i].ID == id {
					if uses, err := dbenrollment.UsesOf(db, id); err == nil {
						data.Keys[i].Consumers = uses
					}
					data.Detail = &data.Keys[i]
					break
				}
			}
		}
	}

	renderAdminTemplate(w, "admin_enroll.html", data)
}

// createEnrollmentKey émet une clé et la retourne pour un affichage unique.
func createEnrollmentKey(r *http.Request, username string, canCreate, isSuperadmin bool) (secret, secretType, message, errMsg string) {
	if !canCreate {
		logs.Write_Log("SECURITY", "webadmin: "+username+" tente d'émettre une clé d'enrôlement sans write:create:client")
		return "", "", "", "Permission refusée : write:create:client requis sur tous les domaines."
	}

	clientType := strings.TrimSpace(r.FormValue("client_type"))
	if err := clienttype.Validate(clientType); err != nil {
		return "", "", "", err.Error()
	}
	if !clienttype.IsService(clientType) {
		return "", "", "", clientType + " est un agent : il se crée depuis la page Clients, il ne s'enrôle pas."
	}

	// Une clé visant un type qui porte l'assertion d'identité donne le pouvoir
	// d'agir au nom de n'importe quel utilisateur. Ce n'est pas un droit qui se
	// délègue par une clé RBAC ordinaire.
	if clienttype.MayAssertUser(clientType) && !isSuperadmin {
		logs.Write_Log("SECURITY", "webadmin: "+username+" tente d'émettre une clé "+clientType+
			" (assertion d'identité) sans appartenir au groupe "+isprotected.ProtectedGroupName)
		return "", "", "", "Permission refusée : une clé " + clientType +
			" permet d'agir au nom de n'importe quel utilisateur. Réservée au groupe " +
			isprotected.ProtectedGroupName + "."
	}

	uses, err := strconv.Atoi(strings.TrimSpace(r.FormValue("uses")))
	if err != nil {
		return "", "", "", "Le quota doit être un nombre entier."
	}
	minutes, err := strconv.Atoi(strings.TrimSpace(r.FormValue("expires_minutes")))
	if err != nil {
		return "", "", "", "La durée doit être un nombre entier de minutes."
	}
	// 0 vaut « illimité » sur les deux bornes. Une clé sans limite ne s'éteint
	// que par révocation : un geste explicite, jamais l'écoulement du temps.
	if uses < 0 || uses > enrollMaxUses {
		return "", "", "", "Le quota doit être compris entre 0 (illimité) et " + strconv.Itoa(enrollMaxUses) + "."
	}
	if minutes < 0 || minutes > enrollMaxMinutes {
		return "", "", "", "La durée doit être comprise entre 0 (sans expiration) et " +
			strconv.Itoa(enrollMaxMinutes/1440) + " jours."
	}

	newSecret, err := dbenrollment.GenerateSecret()
	if err != nil {
		return "", "", "", "Génération impossible : " + err.Error()
	}
	var expiresAt sql.NullTime
	if minutes > 0 {
		expiresAt = sql.NullTime{Time: time.Now().Add(time.Duration(minutes) * time.Minute), Valid: true}
	}

	if _, err := dbenrollment.CreateKey(database.GetDatabase(), newSecret,
		strings.TrimSpace(r.FormValue("label")), clientType, uses, expiresAt, username); err != nil {
		return "", "", "", "Émission impossible : " + err.Error()
	}

	created := "Clé émise. Elle ne sera plus jamais affichée : copiez-la maintenant."
	if uses == 0 || !expiresAt.Valid {
		created += " Cette clé est sans limite : seule une révocation l'arrêtera."
	}
	return newSecret, clientType, created, ""
}

func revokeEnrollmentKey(r *http.Request, username string, canCreate bool) (message, errMsg string) {
	if !canCreate {
		logs.Write_Log("SECURITY", "webadmin: "+username+" tente de révoquer une clé d'enrôlement sans write:create:client")
		return "", "Permission refusée : write:create:client requis sur tous les domaines."
	}
	id, err := strconv.Atoi(strings.TrimSpace(r.FormValue("key_id")))
	if err != nil {
		return "", "Identifiant de clé invalide."
	}
	if err := dbenrollment.RevokeKey(database.GetDatabase(), id, username); err != nil {
		return "", "Révocation impossible : " + err.Error()
	}
	return "Clé révoquée. Les services déjà enrôlés avec elle ne sont pas affectés : " +
		"ils ont leur propre paire de clés.", ""
}

// Bornes de saisie, alignées sur celles du CLI.
//
// Recopiées et non partagées : le CLI les exprime en durée, la page en minutes,
// et les faire transiter par une constante commune obligerait à convertir dans
// les deux sens pour un gain nul. Elles sont de toute façon revalidées par la
// couche base, qui est la seule à faire foi.
const (
	enrollMaxUses    = 50
	enrollMaxMinutes = 7 * 24 * 60
)

// usesText et expiryText rendent lisible l'absence de limite, plutôt que
// d'afficher « 3/0 » ou une date à l'an zéro.
func usesText(k dbenrollment.Record) string {
	if k.UnlimitedUses() {
		return strconv.Itoa(k.UsedCount) + "/∞"
	}
	return strconv.Itoa(k.UsedCount) + "/" + strconv.Itoa(k.MaxUses)
}

func expiryText(k dbenrollment.Record) string {
	if k.NeverExpires() {
		return "jamais"
	}
	return k.ExpiresAt.Time.Format("2006-01-02 15:04")
}

func decorateKey(k dbenrollment.Record, now time.Time) enrollKeyView {
	return enrollKeyView{
		Record:      k,
		Status:      k.Status(now),
		Uses:        usesText(k),
		ExpiresText: expiryText(k),
		CreatedText: k.CreatedAt.Format("2006-01-02 15:04"),
	}
}

// renderAdminTemplate rend une page d'administration avec sa barre latérale.
func renderAdminTemplate(w http.ResponseWriter, name string, data any) {
	tmpl, err := template.ParseFiles(adminTplDir+"/"+name, adminTplDir+"/admin_sidebar.html")
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template "+name+" illisible : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}
	if err := tmpl.Execute(w, data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: rendu de "+name+" échoué : "+err.Error())
	}
}
