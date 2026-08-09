package action

import (
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// Portée DÉCLARÉE par chaque action.
//
// # L'angle mort que ce fichier ferme
//
// La matrice de droits du testrunner substitue la résolution des domaines par
// une portée fixe — sans quoi, faute de base, toutes les portées retomberaient
// sur « droit global exigé » et la délégation par domaine resterait intestée.
//
// Conséquence : elle n'observe JAMAIS quelle portée une action déclare. Passer
// gpo.update de porteeGPO à PorteeGlobale ne faisait échouer aucun test. Or
// c'est exactement la modification qui détruit la délégation : la GPO n'est
// plus contrôlée sur ses propres domaines mais sur « * », donc un délégué perd
// le droit de gérer les GPO de son domaine, et un administrateur global les
// gère toutes sans distinction.
//
// Ce test compare l'IDENTITÉ de la fonction de portée à ce qui est attendu. Il
// ne vérifie pas que la portée est juste — il vérifie qu'elle n'a pas changé
// sans qu'on le veuille, ce qui est la question qu'on peut poser sans base.
//
// # Pourquoi une table, et ce qui l'empêche de vieillir
//
// L'attendu ne se déduit pas du nom : enroll.revoke_key est globale alors
// qu'elle vise une clé précise, parce qu'une clé d'enrôlement n'appartient à
// aucun domaine. Il faut donc l'écrire.
//
// La COUVERTURE, elle, est vérifiée contre le catalogue réel : une action
// ajoutée sans entrée fait échouer le test. Ce n'est donc pas la table qui
// décide de ce qui est éprouvé.

// nomDeFonction rend le nom qualifié d'une fonction.
//
// reflect.ValueOf(f).Pointer() compare les identités mais ne se lit pas dans un
// message d'échec. Le nom permet de dire « attendu porteeGPO, trouvé
// PorteeGlobale », qui se comprend sans ouvrir le code.
func nomDeFonction(f PorteeFunc) string {
	if f == nil {
		return "<nil>"
	}
	complet := runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name()
	if i := strings.LastIndex(complet, "."); i >= 0 {
		return complet[i+1:]
	}
	return complet
}

// porteesAttendues : nom d'action → nom de la fonction de portée.
var porteesAttendues = map[string]string{
	// Créations : la cible n'existe pas encore, elle n'a aucun domaine.
	"user.create":              "PorteeGlobale",
	"group.create":             "PorteeGlobale",
	"client.create":            "PorteeGlobale",
	"permission.create":        "PorteeGlobale",
	"client_permission.create": "PorteeGlobale",
	"gpo.create":               "PorteeGlobale",

	// Utilisateurs : les domaines du compte visé.
	"user.get":             "PorteeUtilisateur",
	"user.update":          "PorteeUtilisateur",
	"user.delete":          "PorteeUtilisateur",
	"user.change_password": "PorteeUtilisateur",
	"user.add_key":         "PorteeUtilisateur",
	"user.remove_key":      "PorteeUtilisateur",
	"user.list_keys":       "PorteeUtilisateur",

	// Le second facteur a sa propre portée, et ce n'est pas une coquetterie :
	// elle porte sur les GROUPES de l'utilisateur et non sur ses domaines.
	// Réinitialiser un second facteur revient à lever une protection pour tous
	// les groupes dont le compte est membre. J'avais écrit PorteeUtilisateur
	// ici par habitude — le test a montré l'écart.
	"user.reset_mfa": "porteeMFAUtilisateur",

	// Groupes.
	"group.get":                      "PorteeGroupe",
	"group.delete":                   "PorteeGroupe",
	"group.list_users":               "PorteeGroupe",
	"group.list_clients":             "PorteeGroupe",
	"group.add_permission":           "PorteeGroupe",
	"group.remove_permission":        "PorteeGroupe",
	"group.set_mfa_required":         "PorteeGroupe",
	"group.add_client_permission":    "PorteeGroupe",
	"group.remove_client_permission": "PorteeGroupe",

	// Rattachements : l'UNION des deux côtés. Voir PorteeGroupeEtUtilisateur.
	"group.add_user":      "PorteeGroupeEtUtilisateur",
	"group.remove_user":   "PorteeGroupeEtUtilisateur",
	"group.add_client":    "PorteeGroupeEtClient",
	"group.remove_client": "PorteeGroupeEtClient",
	"group.add_gpo":       "PorteeGPOEtGroupe",
	"group.remove_gpo":    "PorteeGPOEtGroupe",

	// Machines.
	"client.get":    "PorteeClient",
	"client.update": "PorteeClient",
	"client.delete": "PorteeClient",

	// Permissions : les domaines de la permission visée.
	"permission.get":           "porteePermissionUtilisateur",
	"permission.delete":        "porteePermissionUtilisateur",
	"permission.update_action": "porteePermissionUtilisateur",
	"client_permission.get":    "porteePermissionClient",
	"client_permission.update": "porteePermissionClient",
	"client_permission.delete": "porteePermissionClient",

	// GPO : les domaines des groupes auxquels elle est liée.
	"gpo.get":           "porteeGPO",
	"gpo.update":        "porteeGPO",
	"gpo.delete":        "porteeGPO",
	"gpo.add_module":    "porteeGPO",
	"gpo.update_module": "porteeGPO",
	"gpo.delete_module": "porteeGPO",

	// Listes : globales, réduites ensuite par leur filtre de périmètre.
	"user.list":              "PorteeGlobale",
	"group.list":             "PorteeGlobale",
	"client.list":            "PorteeGlobale",
	"permission.list":        "PorteeGlobale",
	"client_permission.list": "PorteeGlobale",
	"gpo.list":               "PorteeGlobale",

	// Sessions : « qui est connecté en ce moment ». Clé RBAC distincte de
	// read:get:* — savoir qu'un compte existe et savoir qu'il est ouvert sur
	// une machine ne se délèguent pas de la même façon.
	"session.list_users":            "PorteeGlobale",
	"session.get_user":              "PorteeUtilisateur",
	"session.list_users_by_group":   "PorteeGroupe",
	"session.list_clients":          "PorteeGlobale",
	"session.list_clients_by_group": "PorteeGroupe",
	"session.list_clients_by_type":  "PorteeGlobale",

	// Serveur : cluster et certificats. Sans domaine, donc sans portée souple.
	"cluster.list_nodes":      "PorteeGlobale",
	"cluster.get_purge_delay": "PorteeGlobale",
	"cluster.set_purge_delay": "PorteeGlobale",
	"certificate.list":        "PorteeGlobale",
	"certificate.get":         "PorteeGlobale",
	"certificate.regenerate":  "PorteeGlobale",

	// Conformité GPO : la ligne décrit une MACHINE, pas une GPO.
	"gpo.list_compliance": "PorteeGlobale",
	"gpo.get_compliance":  "PorteeClient",

	// Arborescence : même droit que get -g.
	"domain.list_tree":   "PorteeGlobale",
	"domain.list_groups": "porteeDomaine",

	// Réglages et lectures sans domaine.
	"dns.list_zones":        "PorteeGlobale",
	"dns.list_records":      "PorteeGlobale",
	"enroll.list_keys":      "PorteeGlobale",
	"server.set_debug":      "PorteeGlobale",
	"server.clear_sessions": "PorteeGlobale",

	// Sans domaine par nature.
	//
	// Une clé d'enrôlement, une zone DNS, un certificat, la politique de mot
	// de passe : aucun n'appartient à un domaine de l'annuaire. La portée
	// globale n'est pas ici un relâchement, c'est la seule qui ait un sens.
	"enroll.create_key":              "PorteeGlobale",
	"enroll.revoke_key":              "PorteeGlobale",
	"dns.create_zone":                "PorteeGlobale",
	"dns.delete_zone":                "PorteeGlobale",
	"dns.add_record":                 "PorteeGlobale",
	"dns.delete_record":              "PorteeGlobale",
	"dns.delete_ptr":                 "PorteeGlobale",
	"certificate.delete":             "PorteeGlobale",
	"authpolicy.set_password_policy": "PorteeGlobale",
}

// clesAttendues : nom d'action → clé RBAC exigée.
//
// # Pourquoi ce second inventaire
//
// La matrice éprouve la clé de façon RELATIVE : elle accorde `d.CleRBAC` et
// vérifie que l'action passe, refuse quand elle ne l'accorde pas. Elle ne
// regarde jamais QUELLE clé c'est.
//
// Changer `server.set_debug` de `write:server` à `write:update:user` ne faisait
// donc échouer aucun test. Or c'est exactement le défaut que ce lot corrige :
// un réglage de serveur gardé par le droit de modifier des comptes accorde
// beaucoup plus que ce que la commande fait, et son nom ne le laisse pas
// deviner.
//
// La table est écrite, mais sa couverture est vérifiée contre le catalogue
// dans les deux sens — comme pour les portées.
var clesAttendues = map[string]string{
	// Utilisateurs.
	"user.create":          "write:create:user",
	"user.get":             "read:get:user",
	"user.list":            "read:get:user",
	"user.list_keys":       "read:get:user",
	"user.update":          "write:update:user",
	"user.delete":          "write:delete:user",
	"user.change_password": "write:update:user",
	"user.add_key":         "write:update:user",
	"user.remove_key":      "write:update:user",
	"user.reset_mfa":       "write:mfa",

	// Groupes.
	"group.create":                   "write:create:group",
	"group.get":                      "read:get:group",
	"group.list":                     "read:get:group",
	"group.delete":                   "write:delete:group",
	"group.add_user":                 "write:add:user",
	"group.remove_user":              "write:delete:user",
	"group.add_client":               "write:add:client",
	"group.remove_client":            "write:delete:client",
	"group.add_permission":           "write:add:permission",
	"group.remove_permission":        "write:delete:permission",
	"group.add_client_permission":    "write:add:permission",
	"group.remove_client_permission": "write:delete:permission",
	"group.add_gpo":                  "write:add:gpo",
	"group.remove_gpo":               "write:delete:gpo",
	"group.set_mfa_required":         "write:mfa",

	// group.list_users exige read:get:USER et non :group : ce qui est révélé
	// est une liste de comptes.
	"group.list_users":   "read:get:user",
	"group.list_clients": "read:get:client",

	// Machines.
	"client.create": "write:create:client",
	"client.get":    "read:get:client",
	"client.list":   "read:get:client",
	"client.update": "write:update:client",
	"client.delete": "write:delete:client",

	// Permissions.
	"permission.create":        "write:create:permission",
	"permission.get":           "read:get:permission",
	"permission.list":          "read:get:permission",
	"permission.delete":        "write:delete:permission",
	"permission.update_action": "write:update:permission",
	"client_permission.create": "write:create:permission",
	"client_permission.get":    "read:get:permission",
	"client_permission.list":   "read:get:permission",
	"client_permission.update": "write:update:permission",
	"client_permission.delete": "write:delete:permission",

	// GPO. Toutes en *:gpo — voir GPO.CleSpecifiqueAuxGPO dans le testrunner.
	"gpo.create":          "write:create:gpo",
	"gpo.get":             "read:get:gpo",
	"gpo.list":            "read:get:gpo",
	"gpo.update":          "write:update:gpo",
	"gpo.delete":          "write:delete:gpo",
	"gpo.add_module":      "write:update:gpo",
	"gpo.update_module":   "write:update:gpo",
	"gpo.delete_module":   "write:update:gpo",
	"gpo.list_compliance": "read:get:gpo",
	"gpo.get_compliance":  "read:get:gpo",

	// Sessions : clé distincte de read:get:* — savoir qu'un compte existe et
	// savoir qu'il est ouvert sur une machine ne se délèguent pas pareil.
	"session.list_users":            "read:status:user",
	"session.get_user":              "read:status:user",
	"session.list_users_by_group":   "read:status:user",
	"session.list_clients":          "read:status:client",
	"session.list_clients_by_group": "read:status:client",
	"session.list_clients_by_type":  "read:status:client",

	// Arborescence : le même droit que get -g, dont c'est une autre
	// présentation. Employait write:eyes — un droit d'écriture pour une
	// lecture.
	"domain.list_tree":   "read:get:group",
	"domain.list_groups": "read:get:group",

	// Objets sans domaine : actions spéciales dédiées.
	"cluster.list_nodes":      "read:cluster",
	"cluster.get_purge_delay": "read:cluster",
	"cluster.set_purge_delay": "write:cluster",
	"certificate.list":        "read:certificate",
	"certificate.get":         "read:certificate",
	"certificate.regenerate":  "write:certificate",
	"dns.list_zones":          "read:dns",
	"dns.list_records":        "read:dns",
	"enroll.list_keys":        "read:enrollment",
	"server.set_debug":        "write:server",
	"server.clear_sessions":   "write:server",

	// Enrôlement, écriture : reste sur write:create:client, et délibérément.
	// Émettre une clé, c'est accorder le droit d'ajouter un programme au
	// cluster — donc de créer un client.
	"enroll.create_key": "write:create:client",
	"enroll.revoke_key": "write:create:client",

	// DNS, écriture.
	"dns.create_zone":   "write:dns",
	"dns.delete_zone":   "write:dns",
	"dns.add_record":    "write:dns",
	"dns.delete_record": "write:dns",
	"dns.delete_ptr":    "write:dns",

	// Réservées au groupe protégé : aucune clé RBAC ne les couvre, parce que
	// ni un certificat ni la politique de mot de passe n'est une entité de
	// l'annuaire.
	"certificate.delete":             "",
	"authpolicy.set_password_policy": "",
}

func TestChaqueActionDeclareLaCleAttendue(t *testing.T) {
	r := NouveauRegistre()
	enregistrerToutDans(r)

	var ecarts, sansAttendu []string
	vus := map[string]bool{}

	for _, d := range r.Definitions() {
		vus[d.Nom] = true
		attendu, connu := clesAttendues[d.Nom]
		if !connu {
			sansAttendu = append(sansAttendu, d.Nom)
			continue
		}
		if d.CleRBAC != attendu {
			ecarts = append(ecarts,
				d.Nom+" : attendu "+affichable(attendu)+", trouvé "+affichable(d.CleRBAC))
		}
	}

	if len(sansAttendu) > 0 {
		sort.Strings(sansAttendu)
		t.Errorf("actions sans clé attendue déclarée ici — leur clé n'est donc "+
			"vérifiée par rien :\n  %s", strings.Join(sansAttendu, "\n  "))
	}
	if len(ecarts) > 0 {
		sort.Strings(ecarts)
		t.Errorf("clés RBAC qui ont changé :\n  %s", strings.Join(ecarts, "\n  "))
	}

	var mortes []string
	for nom := range clesAttendues {
		if !vus[nom] {
			mortes = append(mortes, nom)
		}
	}
	if len(mortes) > 0 {
		sort.Strings(mortes)
		t.Errorf("entrées de la table qui ne correspondent à aucune action :\n  %s",
			strings.Join(mortes, "\n  "))
	}
}

// affichable rend une clé vide lisible dans un message d'échec.
//
// « attendu , trouvé write:update:user » se lit mal ; « attendu (aucune clé) »
// dit ce qu'il faut.
func affichable(cle string) string {
	if cle == "" {
		return "(aucune clé — groupe protégé)"
	}
	return cle
}

func TestChaqueActionDeclareLaPorteeAttendue(t *testing.T) {
	r := NouveauRegistre()
	// Un registre neuf plutôt que le catalogue partagé : celui-ci peut avoir
	// été garni par un autre test du paquet, et l'ordre d'exécution déciderait
	// alors du résultat.
	enregistrerToutDans(r)

	var ecarts, sansAttendu []string
	vus := map[string]bool{}

	for _, d := range r.Definitions() {
		vus[d.Nom] = true
		attendu, connu := porteesAttendues[d.Nom]
		if !connu {
			sansAttendu = append(sansAttendu, d.Nom)
			continue
		}
		if got := nomDeFonction(d.Portee); got != attendu {
			ecarts = append(ecarts, d.Nom+" : attendu "+attendu+", trouvé "+got)
		}
	}

	if len(sansAttendu) > 0 {
		sort.Strings(sansAttendu)
		t.Errorf("actions sans portée attendue déclarée dans ce test — leur portée "+
			"n'est donc vérifiée par rien :\n  %s", strings.Join(sansAttendu, "\n  "))
	}
	if len(ecarts) > 0 {
		sort.Strings(ecarts)
		t.Errorf("portées qui ont changé :\n  %s", strings.Join(ecarts, "\n  "))
	}

	// La table ne doit pas non plus porter d'entrées mortes : une action
	// renommée laisserait sinon une ligne qui ne vérifie plus rien.
	var mortes []string
	for nom := range porteesAttendues {
		if !vus[nom] {
			mortes = append(mortes, nom)
		}
	}
	if len(mortes) > 0 {
		sort.Strings(mortes)
		t.Errorf("entrées de la table qui ne correspondent à aucune action :\n  %s",
			strings.Join(mortes, "\n  "))
	}
}

// enregistrerToutDans garnit un registre donné.
//
// EnregistrerTout ne sait garnir que le catalogue partagé. Dupliquer la liste
// serait exactement le défaut corrigé ailleurs — deux inventaires qui
// divergent — mais ici la duplication est CONSTATÉE par le test lui-même :
// une action absente d'ici l'est aussi du registre construit, donc son nom
// figure dans « entrées mortes » de la table ci-dessus.
func enregistrerToutDans(r *Registre) {
	EnregistrerActionsUtilisateur(r)
	EnregistrerActionsClesUtilisateur(r)
	EnregistrerActionsSuppressionUtilisateur(r)
	EnregistrerActionsMFA(r)
	EnregistrerActionsGroupe(r)
	EnregistrerActionsClient(r)
	EnregistrerActionsPermission(r)
	EnregistrerActionsGrammairePermission(r)
	EnregistrerActionsCertificat(r)
	EnregistrerActionsEnrolement(r)
	EnregistrerActionsDNS(r)
	EnregistrerActionsPolitiqueMotDePasse(r)
	EnregistrerActionsLecture(r)
	EnregistrerActionsLectureSuite(r)
	EnregistrerActionsGPO(r)
	EnregistrerActionsLectureEtat(r)
	EnregistrerActionsServeur(r)
	EnregistrerActionsConformiteGPO(r)
	EnregistrerActionsArborescence(r)
	EnregistrerActionsReglages(r)
}
