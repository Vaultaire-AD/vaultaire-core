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
	"html/template"
	"net/http"
	"strconv"
	"time"

	"vaultaire/core/clienttype"
	"vaultaire/core/database"
	dbenrollment "vaultaire/core/database/db_enrollment"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
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

	// read:enrollment, et non plus read:get:client.
	//
	// Le commentaire d'origine annonçait « même clé RBAC que le CLI ». Ce n'est
	// plus vrai depuis que les clés d'enrôlement ont la leur : `enroll list`
	// exige `read:enrollment`, cette page se contentait de `read:get:client`.
	//
	// L'écart n'était pas anodin. `read:get:client` est le droit de lire les
	// MACHINES, délégué par domaine et détenu par tout administrateur de
	// périmètre : il ouvrait donc la liste des clés d'enrôlement — qui
	// permettent de faire naître un service parlant au cluster entier — à qui
	// n'avait qu'une délégation locale.
	//
	// Même défaut que la page des certificats : deux façades, deux réponses à
	// la même question. Voir AdminCertificatesHandler.
	if !checkWebAdminRBAC(w, r, groupIDs, permission.ActionReadEnrollment) {
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
		// Toutes les actions passent par le registre. Les contrôles de droits —
		// write:create:client, et l'appartenance au groupe protégé pour les
		// types qui portent l'assertion d'identité — sont portés par la
		// définition de l'action, plus par ce fichier.
		//
		// Les deux fonctions createEnrollmentKey et revokeEnrollmentKey qui
		// vivaient ici ont disparu avec leurs contrôles : les garder aurait
		// laissé deux endroits où le droit se décide, donc deux endroits à
		// tenir d'accord.
		res, traite, err := ExecuterActionFormulaire(r, username, groupIDs)
		if traite {
			if err != nil {
				data.Error = MessageDActionPourAffichage(res, err)
			} else {
				data.Message = res.Message
				// Le secret ne voyage jamais dans le message — il finirait dans
				// les journaux, où le message d'exécution est recopié. Il est
				// dans les données, et n'est lu qu'ici, pour un affichage
				// unique.
				if d, ok := res.Donnees.(map[string]string); ok {
					data.Secret, data.SecretType = d["secret"], d["client_type"]
				}
			}
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

// Les fonctions createEnrollmentKey et revokeEnrollmentKey ont été retirées.
//
// Elles portaient leurs propres contrôles de droits — write:create:client, et
// l'appartenance au groupe protégé pour les types capables d'agir au nom d'un
// utilisateur — ainsi que la validation des bornes de saisie.
//
// Tout cela vit désormais dans la définition des actions enroll.create_key et
// enroll.revoke_key (core/action/actions_enroll.go). Les garder ici aurait
// laissé DEUX endroits où le droit se décide : la ligne de commande aurait pu
// diverger de l'interface web sans que rien ne le signale — c'est exactement ce
// qui s'était produit pour la création d'utilisateur.
//
// Les bornes de saisie ont suivi le même chemin.
//
// Elles vivaient ici ET dans le CLI, recopiées « parce que le CLI les exprime
// en durée et la page en minutes ». C'était une justification de la
// duplication, pas une raison de la garder : les deux se sont ensuite
// contredites sur le message affiché, sinon sur la valeur.
//
// Elles sont maintenant dans l'action, une fois.

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
	tmpl, err := template.ParseFiles(CheminGabarit(name), CheminGabarit("admin_sidebar.html"))
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: template "+name+" illisible : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
		return
	}
	if err := rendreGabarit(w, tmpl, data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "webadmin: rendu de "+name+" échoué : "+err.Error())
		http.Error(w, "Erreur interne du serveur", http.StatusInternalServerError)
	}
}
