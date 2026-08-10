package webserveur

import (
	"bytes"
	"html/template"
	"net/http"
	"strings"
	"vaultaire/core/command"
	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"
)

// adminTplDir a disparu au profit de CheminGabarit : le chemin des gabarits
// n'est plus écrit qu'à un seul endroit, dans web_assets.go.

// rendreDansTampon exécute un gabarit EN MÉMOIRE avant d'écrire quoi que ce
// soit dans la réponse.
//
// # Le défaut que cela corrige
//
// `tmpl.Execute(w, data)` écrit au fil de l'exécution. Si le gabarit échoue au
// milieu — le cas le plus courant étant un champ que la structure de données ne
// porte pas ou plus —, tout ce qui précède la ligne fautive est DÉJÀ parti dans
// la réponse, et tout ce qui suit ne partira jamais.
//
// Le résultat, côté navigateur, est une page tronquée qui ne ressemble pas du
// tout à une erreur :
//
//   - le contenu s'arrête net, sans message : la page « n'affiche plus rien » ;
//   - `<script src="/static/app.js">` étant en bas du document, il n'est jamais
//     envoyé — donc le thème choisi ne s'applique plus, la barre latérale ne
//     fonctionne plus, et rien n'indique pourquoi ;
//   - le `http.Error` de secours arrive après l'en-tête déjà écrit et ne fait
//     qu'ajouter « superfluous response.WriteHeader » aux journaux, sans
//     atteindre l'utilisateur.
//
// Trois symptômes sans rapport apparent pour une seule cause, et aucun qui
// désigne le gabarit. C'est ce qui rend ce mode de panne coûteux à diagnostiquer.
//
// En rendant dans un tampon, l'échec se produit AVANT le premier octet : la
// réponse est alors intacte, `http.Error` fonctionne, et le message d'erreur
// nomme le gabarit et le champ fautif.
//
// Le coût est une page en mémoire le temps du rendu — quelques dizaines de
// kilo-octets pour les plus grosses d'entre elles.
func rendreDansTampon(w http.ResponseWriter, tmpl *template.Template, nom string, data interface{}) error {
	var tampon bytes.Buffer
	if err := tmpl.ExecuteTemplate(&tampon, nom, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := tampon.WriteTo(w)
	return err
}

// rendreGabarit est la même protection pour les gabarits d'un seul fichier —
// connexion, profil, second facteur, enrôlement —, qui appellent `Execute` et
// non `ExecuteTemplate`.
//
// Ces pages-là sont les plus sensibles au problème : la page de profil est la
// destination de TOUTES les redirections de refus d'accès. Si elle se tronque,
// l'utilisateur renvoyé vers elle voit une page vide et conclut que c'est la
// page d'origine qui est cassée.
func rendreGabarit(w http.ResponseWriter, tmpl *template.Template, data interface{}) error {
	var tampon bytes.Buffer
	if err := tmpl.Execute(&tampon, data); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err := tampon.WriteTo(w)
	return err
}

// executeAdminPage parse le partial sidebar + la page et exécute la page (sidebar commun à toutes les pages admin).
func executeAdminPage(w http.ResponseWriter, pageName string, data interface{}) error {
	tmpl, err := template.ParseFiles(CheminGabarit("admin_sidebar.html"), CheminGabarit(pageName))
	if err != nil {
		// Journalisé ici : les appelants rendent tous « Template manquant », un
		// message qui vaut pour l'analyse syntaxique mais induit en erreur quand
		// c'est l'exécution qui a échoué — le fichier est bien là.
		logs.Write_Log("ERROR", "web: analyse du gabarit "+pageName+" impossible : "+err.Error())
		return err
	}
	if err := rendreDansTampon(w, tmpl, pageName, data); err != nil {
		logs.Write_Log("ERROR", "web: exécution du gabarit "+pageName+" échouée : "+err.Error())
		return err
	}
	return nil
}

// requireWebAdmin checks session and web_admin permission; if not allowed, redirects to / or /profil and returns false.
func requireWebAdmin(w http.ResponseWriter, r *http.Request) (username string, ok bool) {
	// La validation du jeton ET la restriction « mot de passe expiré » sont dans
	// requireLogin : aucune page d'administration ne doit être atteignable avec
	// un mot de passe expiré, et le contrôle ne doit exister qu'à un seul endroit.
	username, _, ok = requireLogin(w, r, false)
	if !ok {
		return "", false
	}
	groupIDs, action, err := permission.PrePermissionCheck(username, "web_admin")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return "", false
	}
	allowed, _ := permission.CheckPermissionsMultipleDomains(groupIDs, action, []string{"*"})
	if !allowed {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return "", false
	}
	return username, true
}

// requireWebAdminWithGroupIDs does requireWebAdmin then returns the user's groupIDs (same as command package uses for RBAC).
// Use with permission.CheckPermissionsMultipleDomains(groupIDs, actionKey, domains) for entity-specific checks.
func requireWebAdminWithGroupIDs(w http.ResponseWriter, r *http.Request) (username string, groupIDs []int, ok bool) {
	username, ok = requireWebAdmin(w, r)
	if !ok {
		return "", nil, false
	}
	groupIDs, err := permission.GetGroupIDsForUser(username)
	if err != nil {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return "", nil, false
	}
	return username, groupIDs, true
}

// Deux contrôles distincts, et les confondre était le défaut de l'interface.
//
// `web_admin` est la porte d'entrée : sans lui, aucune page d'administration.
// Il est global par nature (voir permission.IsGlobalOnlyAction) et vérifié une
// fois par requireWebAdmin.
//
// Ensuite viennent les droits RBAC, exactement comme en ligne de commande où
// `web_admin` n'entre jamais en jeu. Mais l'interface les vérifiait toujours
// contre « * », c'est-à-dire en exigeant le droit global : un administrateur
// délégué sur un domaine se retrouvait capable de tout faire en CLI et de rien
// faire en web. La séparation ci-dessous corrige ça :
//
//   - checkWebAdminRBAC          : « as-tu quelque chose à faire sur cette
//     page ? » — le droit sur au moins un domaine suffit à l'ouvrir ;
//   - checkWebAdminRBACOnDomains : « as-tu le droit sur CETTE entité ? » — le
//     droit est exigé sur chacun de ses domaines, comme en CLI.
//
// Ouvrir une page ne donne donc aucun pouvoir : chaque action reste contrôlée
// sur sa cible.

// checkWebAdminRBAC autorise l'accès à une page dès lors que l'action est
// accordée quelque part. Redirige vers /profil sinon.
func checkWebAdminRBAC(w http.ResponseWriter, r *http.Request, groupIDs []int, actionKey string) bool {
	if !permission.HasActionAnywhere(groupIDs, actionKey) {
		http.Redirect(w, r, "/profil", http.StatusSeeOther)
		return false
	}
	return true
}

// checkWebAdminRBACOnDomains vérifie une action sur les domaines d'une entité
// précise. Ne redirige pas : l'appelant affiche le refus dans la page, pour que
// l'administrateur comprenne quel droit lui manque au lieu d'être renvoyé sans
// explication.
func checkWebAdminRBACOnDomains(groupIDs []int, actionKey string, domains []string) (bool, string) {
	return permission.CheckPermissionsAllDomains(groupIDs, actionKey, domains)
}

// canDeleteCertificate a été retirée.
//
// Elle vérifiait l'appartenance au groupe protégé avant une suppression de
// certificat. Ce contrôle vit désormais dans l'action certificate.delete, qui
// le déclare par ExigeSuperadmin — donc au même endroit que l'effet, et donc
// partagé avec la ligne de commande le jour où elle exposera cette opération.
//

// entityDomainsOrGlobal a quitté ce fichier.
//
// Elle réduisait une erreur de résolution de domaines à un refus : ne pas
// savoir à quels domaines appartient une entité n'autorise rien. Son dernier
// appelant était le contrôle de update_permission_action, désormais dans le
// registre — qui applique la même règle par domainesOuGlobal, avec une nuance
// de plus : il exige le droit GLOBAL au lieu de laisser une liste vide, ce qui
// ne dépend plus de la façon dont le vérificateur traite le vide.

// AdminIndexHandler serves the admin dashboard and executes CLI-style commands via POST.
func AdminIndexHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := requireWebAdmin(w, r)
	if !ok {
		return
	}

	data := struct {
		Username                string
		Output                  string
		DnsEnable               bool
		Section                 string
		Debug                   bool
		LoginClientPublicKey    string
		LoginClientAddKeyScript string
	}{Username: username, DnsEnable: storage.Dns_Enable, Section: "dashboard", Debug: storage.Debug}

	// Load login client public key for "client -join" copy-paste
	if cert, err := dbcertificates.GetCertificateByName(duckykey.ServerLoginClientKeyName); err == nil && cert.PublicKeyData != nil {
		pub := strings.TrimSpace(*cert.PublicKeyData)
		data.LoginClientPublicKey = pub
		// Escape single quotes for use inside shell '...'
		pubEsc := strings.ReplaceAll(pub, "'", "'\"'\"'")
		data.LoginClientAddKeyScript = "#!/bin/sh\n# Add Vaultaire server public key to root@client (for client -join)\n# Run as root on the client machine.\nmkdir -p /root/.ssh\necho '" + pubEsc + "' >> /root/.ssh/authorized_keys\nchmod 700 /root/.ssh\nchmod 600 /root/.ssh/authorized_keys\n"
	}

	if r.Method == http.MethodPost {
		if r.FormValue("action") == "set_debug" {
			storage.Debug = r.FormValue("debug") == "on" || r.FormValue("debug") == "1"
		} else {
			cmd := strings.TrimSpace(r.FormValue("command"))
			if cmd != "" {
				data.Output = command.ExecuteCommand(cmd, username)
			}
		}
		data.Debug = storage.Debug
	}

	if err := executeAdminPage(w, "admin.html", data); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeWebTemplate, "admin template: "+err.Error())
		http.Error(w, "Template manquant", http.StatusInternalServerError)
	}
}
