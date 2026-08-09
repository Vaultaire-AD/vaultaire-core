package permission

import (
	"strings"
)

// Objets et actions RBAC (catégorie:action:objet)
var (
	RBACObjects   = []string{"user", "group", "client", "permission", "gpo"}
	RBACRead      = []string{"get", "status"}
	RBACWrite     = []string{"create", "delete", "update", "add"}
	legacyActions = []string{"none", "web_admin", "auth", "compare", "search"}

	// specialActions sont les commandes qui ne se rangent pas dans le modèle
	// catégorie:action:objet. Elles étaient énumérées à trois endroits (ici,
	// l'interface web, le CLI) : la liste vit désormais ici seule, sinon en
	// ajouter une la rendrait invisible dans l'interface sans que rien ne le
	// signale.
	specialActions = []string{
		"write:dns", "write:eyes",
		ActionKillSwitch, ActionReadLog, ActionManageMFA,
		ActionReadCluster, ActionWriteCluster,
		ActionReadCertificate, ActionWriteCertificate,
		ActionReadDNS, ActionReadEnrollment, ActionWriteServer,
	}
)

// ActionReadDNS est le droit de CONSULTER la configuration DNS.
//
// # Pourquoi une clé de lecture séparée de write:dns
//
// Les lectures — lister les zones, afficher les enregistrements — étaient
// gardées par `write:dns`, c'est-à-dire par le droit de MODIFIER le DNS. Voir
// quels noms le serveur résout n'a rien à voir avec le pouvoir de les changer :
// on veut pouvoir confier la première à un support de niveau 1 sans lui donner
// la seconde.
//
// Le défaut était le même que `write:eyes` gardant une commande de lecture : le
// nom disait le contraire de ce que la clé protégeait.
const ActionReadDNS = "read:dns"

// ActionReadEnrollment est le droit de consulter les clés d'enrôlement.
//
// # Ce qu'elle remplace
//
// `enroll list` et `enroll show` empruntaient `read:get:client` sur « * » —
// donc le droit de lire toutes les machines de tous les domaines pour voir la
// liste des clés en attente. Une clé d'enrôlement n'appartient pourtant à aucun
// domaine ; c'est le même cas que le cluster et les certificats.
//
// # Ce qu'elle ne remplace pas
//
// L'ÉMISSION et la RÉVOCATION d'une clé restent sur `write:create:client`, et
// délibérément : émettre une clé d'enrôlement, c'est accorder le droit
// d'ajouter un programme au cluster — donc de créer un client. La clé qui
// gouverne cet effet est bien celle-là.
//
// Seule la consultation méritait d'être séparée.
const ActionReadEnrollment = "read:enrollment"

// ActionWriteServer est le droit de modifier un RÉGLAGE du serveur.
//
// # Ce qu'elle remplace
//
// `update -debug` et `clear` (purge des sessions expirées) empruntaient
// `write:update:user`. Régler le mode debug ou vider une table de sessions n'a
// rien d'une modification de compte : la clé accordait beaucoup plus que ce que
// la commande fait, et son nom ne laissait pas deviner qu'elle ouvrait ces
// deux-là.
//
// Une seule clé pour les deux : ce sont des réglages d'exploitation, sans
// distinction utile entre eux. Le jour où l'un pèsera plus lourd que l'autre,
// il méritera la sienne.
const ActionWriteServer = "write:server"

// ActionReadCluster et ActionWriteCluster : consultation et réglage du cluster.
//
// # Pourquoi des actions spéciales et non un objet RBAC
//
// Un nœud de cluster n'est pas une entité de l'annuaire : il n'appartient à
// aucun domaine, et la délégation par domaine n'a donc rien à quoi s'appliquer.
// Le déclarer dans RBACObjects engendrerait six clés — read:get:cluster,
// write:add:cluster… — dont deux seulement auraient un sens. Une clé qui
// n'accorde rien est indiscernable d'un oubli.
//
// C'est le motif déjà employé pour read:log, write:dns, write:mfa et
// write:killswitch, et pour la même raison à chaque fois.
//
// # Ce qu'elles remplacent
//
// La commande cluster empruntait read:get:client et write:update:client sur
// « * ». Deux conséquences : voir l'état du cluster exigeait le droit de lire
// TOUTES les machines de TOUS les domaines, et régler le délai de purge
// emportait celui de les modifier. Deux responsabilités très différentes
// portées par la même clé.
const (
	ActionReadCluster  = "read:cluster"
	ActionWriteCluster = "write:cluster"
)

// ActionReadCertificate et ActionWriteCertificate : certificats TLS du serveur.
//
// Même raisonnement : un certificat n'appartient à aucun domaine — c'est
// d'ailleurs pourquoi sa suppression exige l'appartenance au groupe protégé
// plutôt qu'une clé RBAC.
//
// # Ce qu'elles remplacent, et pourquoi c'était trop large
//
// `certificate list` et `show` empruntaient read:get:client ; `regenerate`
// empruntait write:create:client. Or régénérer le certificat LDAPS change
// l'empreinte que TOUT le parc a importée dans son magasin de confiance : les
// clients cessent de se connecter jusqu'à réimport. Confier cela à quiconque
// peut créer une machine était disproportionné dans un sens, et exiger de
// pouvoir créer des machines pour simplement LIRE le certificat public l'était
// dans l'autre.
const (
	ActionReadCertificate  = "read:certificate"
	ActionWriteCertificate = "write:certificate"
)

// ActionManageMFA est le droit de réinitialiser le second facteur d'un tiers.
//
// Action spéciale et non clé RBAC : le second facteur n'est pas un objet de
// l'annuaire, et les six clés qu'un objet « mfa » engendrerait n'auraient qu'un
// seul sens utile.
//
// Séparée de write:update:user à dessein, et pour les deux raisons à la fois.
// Débloquer un téléphone perdu est une tâche de support, fréquente et peu
// risquée : l'y confier ne doit pas emporter le droit de renommer ou de
// reconfigurer des comptes. Inversement, qui gère l'annuaire au quotidien ne
// devrait pas pouvoir retirer silencieusement le second facteur d'un
// administrateur — ce serait le moyen le plus discret de préparer une reprise de
// compte.
//
// Contrairement à read:log et write:dns, ce droit N'EST PAS dans
// globalOnlyActions : réinitialiser le MFA vise un compte, qui appartient à des
// domaines. Il se délègue donc par domaine comme les autres droits sur les
// utilisateurs, et il est vérifié sur TOUS les domaines de la cible.
const ActionManageMFA = "write:mfa"

// ActionReadLog est le droit de consulter les journaux du serveur.
//
// Action spéciale et non clé RBAC à trois segments : un journal n'est pas un
// objet de l'annuaire. Le déclarer comme tel créerait six clés
// (read:get:log, write:create:log…) dont une seule aurait un sens.
//
// Séparée des autres droits de lecture à dessein. Les journaux traversent tous
// les domaines : ils contiennent les tentatives d'authentification, les refus de
// permission et les déclenchements de kill switch de TOUT le parc. Quelqu'un qui
// administre un domaine n'a pas à y lire l'activité des autres, et quelqu'un qui
// doit auditer le serveur n'a pas besoin de pouvoir modifier l'annuaire pour
// autant.
//
// Voir aussi globalOnlyActions : ce droit ne se restreint pas par domaine,
// puisqu'une ligne de journal n'en porte pas.
const ActionReadLog = "read:log"

// ActionKillSwitch est le droit de déclencher une révocation de compte.
//
// Une action spéciale plutôt qu'un verbe RBAC : les verbes sont un produit
// cartésien avec les objets, ajouter « revoke » créerait six clés
// (write:revoke:user, :group, :client…) dont une seule aurait un sens.
//
// Séparée de write:delete:user à dessein. On veut pouvoir confier la
// désactivation d'urgence à une équipe de permanence — support, astreinte —
// sans lui donner le droit de supprimer des comptes au quotidien. Et
// inversement : gérer les départs ne devrait pas emporter le pouvoir de couper
// n'importe qui instantanément. Le mode `hard`, lui, exige les deux.
const ActionKillSwitch = "write:killswitch"

// globalOnlyActions sont les actions dont le contrôle passe toujours le domaine
// « * », quelle que soit la cible.
//
// Leur donner une liste de domaines ne les restreint pas : cela les refuse,
// puisque aucun domaine nommé ne correspond à « * ». Pour web_admin la
// conséquence est brutale — l'auteur du changement perd l'accès à l'interface
// d'administration, y compris pour se corriger.
//
// Vérifié aux appelants : web_admin dans web_serveur/web_admin.go et
// web_profil.go, write:dns dans command_dns/command_dns_manager.go. Si un de ces
// appels venait à transmettre un domaine réel, il faudrait retirer l'entrée
// correspondante ici.
//
// Le cluster et les certificats y figurent pour la même raison que les
// journaux : ni un nœud ni un certificat ne porte de domaine, donc leur donner
// une liste de domaines les refuserait au lieu de les restreindre.
var globalOnlyActions = []string{
	"web_admin", "write:dns", ActionReadLog,
	ActionReadCluster, ActionWriteCluster,
	ActionReadCertificate, ActionWriteCertificate,
	ActionReadDNS, ActionReadEnrollment, ActionWriteServer,
}

// IsGlobalOnlyAction dit si une action ne s'évalue que sur « * », et n'accepte
// donc que nil ou all.
func IsGlobalOnlyAction(key string) bool {
	for _, a := range globalOnlyActions {
		if a == key {
			return true
		}
	}
	return false
}

// AllActionKeys retourne TOUTES les actions administrables : RBAC, legacy et
// spéciales.
//
// Source de vérité unique pour tout ce qui doit énumérer les droits. Le
// peuplement de la permission d'amorçage `vaultaire_all` s'appuie dessus : sa
// liste était auparavant recopiée à la main dans le SQL de Create_DataBase, et
// elle a dérivé dès le premier ajout — `write:killswitch` n'y figurait pas, si
// bien que le groupe superadmin lui-même n'avait pas le droit de déclencher le
// kill switch, et que le bouton n'apparaissait dans aucune interface.
func AllActionKeys() []string {
	keys := make([]string, 0, len(legacyActions)+len(specialActions)+len(RBACObjects)*6)
	keys = append(keys, legacyActions...)
	keys = append(keys, AllRBACActionKeys()...)
	keys = append(keys, specialActions...)
	return keys
}

// LegacyActionKeys retourne les actions historiques, hors modèle RBAC.
func LegacyActionKeys() []string { return append([]string(nil), legacyActions...) }

// SpecialActionKeys retourne les commandes spéciales, hors modèle RBAC.
func SpecialActionKeys() []string { return append([]string(nil), specialActions...) }

// Liste des actions valides (legacy + RBAC)
var validActions = buildValidActions()

func buildValidActions() []string {
	list := make([]string, 0, 50)
	list = append(list, legacyActions...)
	for _, obj := range RBACObjects {
		for _, a := range RBACRead {
			list = append(list, "read:"+a+":"+obj)
		}
		for _, a := range RBACWrite {
			list = append(list, "write:"+a+":"+obj)
		}
	}
	list = append(list, specialActions...)
	return list
}

// IsValidAction vérifie si une action est valide et retourne le nom normalisé
func IsValidAction(action string) (string, bool) {
	action = strings.ToLower(action)
	for _, a := range validActions {
		if a == action {
			return a, true
		}
	}
	// Accepte aussi le format catégorie:action:objet si cohérent
	if IsRBACActionKey(action) {
		return action, true
	}
	return action, false
}

// IsRBACActionKey retourne true si la chaîne respecte le format catégorie:action:objet
func IsRBACActionKey(key string) bool {
	parts := strings.Split(key, ":")
	if len(parts) != 3 {
		return false
	}
	cat, act, obj := strings.ToLower(parts[0]), strings.ToLower(parts[1]), strings.ToLower(parts[2])
	if cat != "read" && cat != "write" {
		return false
	}
	objOk := false
	for _, o := range RBACObjects {
		if o == obj {
			objOk = true
			break
		}
	}
	if !objOk {
		return false
	}
	if cat == "read" {
		for _, a := range RBACRead {
			if a == act {
				return true
			}
		}
	}
	if cat == "write" {
		for _, a := range RBACWrite {
			if a == act {
				return true
			}
		}
	}
	return false
}

// AllRBACActionKeys retourne la liste de toutes les clés RBAC (pour l'admin)
func AllRBACActionKeys() []string {
	var keys []string
	for _, obj := range RBACObjects {
		for _, a := range RBACRead {
			keys = append(keys, "read:"+a+":"+obj)
		}
		for _, a := range RBACWrite {
			keys = append(keys, "write:"+a+":"+obj)
		}
	}
	return keys
}
