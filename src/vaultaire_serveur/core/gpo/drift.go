package gpo

import (
	"fmt"
	"strings"
)

// Suivi de dérive — ce que l'agent constate entre deux applications.
//
// # La question à laquelle le rapport d'application ne répond pas
//
// 05_12 dit « j'ai appliqué la politique X avec succès ». C'est vrai au moment
// où c'est dit, et faux dès que quelqu'un édite un fichier à la main. Sans
// vérification ultérieure, une machine reste affichée conforme indéfiniment sur
// la foi d'une application qui date de trois semaines — l'erreur d'un tableau de
// bord n'est pas d'être vide, c'est d'être rassurant à tort.
//
// 05_15 répond à l'autre question : est-ce ENCORE vrai ?

// DriftMode décide de ce que l'agent FAIT d'un écart constaté.
//
// # Pourquoi la décision vient d'ici et non de l'agent
//
// Le mode a longtemps été une variable du binaire client, avec le commentaire
// « destinée à être relue depuis la configuration de l'agent ». Personne ne la
// relisait : le mode audit était inatteignable en production, donc du code mort.
//
// Le remettre dans un fichier de l'agent aurait déplacé le problème sans le
// résoudre. La machine est justement celle qui dérive : lui confier le réglage
// qui décide si sa dérive est corrigée revient à laisser la question à la partie
// qui a un intérêt dans la réponse. Un poste dont quelqu'un a édité
// /etc/vaultaire/client_software.yaml aurait pu se déclarer en audit et n'être
// plus jamais corrigé, sans que rien ne le signale côté serveur.
//
// # Pourquoi le mode est porté par la GPO
//
// Un parc n'est pas homogène. Un groupe « laboratoire » où les interventions
// manuelles sont légitimes veut du signalement ; le reste du parc veut de la
// correction. Deux binaires pour ça n'était pas tenable. Le mode est donc un
// attribut de la GPO, et un module hérite du mode de la GPO qui le porte : une
// machine qui reçoit les deux applique la règle de chacun, module par module,
// au lieu d'un compromis qui trahirait l'une ou l'autre.
type DriftMode string

const (
	// DriftEnforce : l'écart est signalé ET corrigé au cycle suivant. C'est ce
	// qu'on attend d'une politique — un annuaire qui constate sans reprendre la
	// main n'est plus une source de vérité.
	DriftEnforce DriftMode = "enforce"
	// DriftAudit : l'écart est signalé, rien n'est corrigé.
	//
	// À réserver aux parcs où des interventions manuelles légitimes existent.
	// Une GPO qui n'est plus appliquée et reste affichée comme conforme est pire
	// que pas de GPO du tout : c'est pourquoi ce mode signale toujours, et
	// pourquoi il n'est pas le défaut.
	DriftAudit DriftMode = "audit"
)

// DefaultDriftMode est le mode d'une GPO qui n'en déclare pas.
//
// Enforce, et non audit : le défaut d'un mécanisme de conformité doit être de
// faire respecter la configuration. Un défaut permissif transformerait chaque
// oubli de réglage en machine silencieusement non corrigée.
const DefaultDriftMode = DriftEnforce

// IsValidDriftMode indique si un mode est reconnu.
func IsValidDriftMode(m string) bool {
	switch DriftMode(m) {
	case DriftEnforce, DriftAudit:
		return true
	}
	return false
}

// NormalizeDriftMode interprète une valeur saisie et rend le mode correspondant.
//
// Une valeur VIDE rend le défaut sans erreur : c'est le cas d'une GPO créée
// avant l'existence de la colonne, et d'une base dont la migration vient de
// poser la colonne. Une valeur non vide et inconnue est en revanche refusée
// plutôt que ramenée au défaut — « enfrce » deviendrait sinon silencieusement
// enforce aujourd'hui, et personne ne verrait la faute de frappe le jour où le
// même geste voudra dire audit.
func NormalizeDriftMode(raw string) (DriftMode, error) {
	clean := strings.ToLower(strings.TrimSpace(raw))
	if clean == "" {
		return DefaultDriftMode, nil
	}
	if !IsValidDriftMode(clean) {
		return "", fmt.Errorf("mode de dérive %q invalide (attendu : %s ou %s)",
			raw, DriftEnforce, DriftAudit)
	}
	return DriftMode(clean), nil
}

// DriftKind qualifie un écart constaté sur un fichier déployé.
type DriftKind string

const (
	// DriftModified : le contenu ne correspond plus à l'empreinte enregistrée.
	DriftModified DriftKind = "modified"
	// DriftMissing : le fichier a disparu.
	DriftMissing DriftKind = "missing"
	// DriftUnreadable : le fichier existe mais ne peut pas être relu — droits,
	// montage absent, disque en erreur. Distingué de « modifié » parce qu'il
	// n'appelle pas la même action : ici on ne sait pas, on ne constate pas.
	DriftUnreadable DriftKind = "unreadable"
	// DriftPermissions : contenu conforme, mode changé. Un fichier de clés
	// passé en 0644 est un incident de sécurité alors que son contenu est
	// intact ; les confondre le rendrait invisible.
	DriftPermissions DriftKind = "permissions"
	// DriftReappeared : un fichier que la politique RETIRE a été recréé.
	//
	// L'exact opposé de DriftMissing, et il fallait les distinguer : ils ne se
	// lisent pas de la même façon. « Disparu » se lit comme un effacement par
	// erreur ; « réapparu » se lit comme une interdiction contournée — un module
	// noyau réautorisé, un dépôt de paquets remis, un durcissement PAM annulé.
	//
	// Cette valeur n'existait pas côté agent avant le point 4 : un module dont
	// l'effet est « ce fichier ne doit pas exister » ne laissait aucune trace, et
	// le recréer ne produisait donc aucun écart.
	DriftReappeared DriftKind = "reappeared"
	// DriftSystemState : un effet NON-fichier ne tient plus — service réactivé,
	// règle nftables disparue, compte remis dans sudo. Le fichier qui décrit
	// l'état voulu peut être intact : c'est l'état lui-même qui a bougé.
	//
	// Le champ Path porte alors la CIBLE et non un chemin : un nom d'unité
	// systemd, un couple utilisateur/groupe. La colonne est réutilisée plutôt
	// que doublée — les deux répondent à « sur quoi », et une seconde colonne
	// vide neuf fois sur dix compliquerait toutes les vues pour rien.
	DriftSystemState DriftKind = "system_state"
	// DriftUnverifiable : l'état n'a pas pu être constaté — commande absente,
	// délai dépassé. Le pendant de DriftUnreadable pour les effets non-fichier,
	// et distinct de DriftSystemState pour la même raison : ici on ne sait pas.
	DriftUnverifiable DriftKind = "unverifiable"
)

// IsValidDriftKind indique si un type d'écart est reconnu.
//
// Fail-closed comme partout ailleurs : un agent qui inventerait un type verrait
// sa ligne écartée, pas enregistrée sous une valeur que rien n'interprète.
func IsValidDriftKind(k string) bool {
	switch DriftKind(k) {
	case DriftModified, DriftMissing, DriftUnreadable, DriftPermissions,
		DriftReappeared, DriftSystemState, DriftUnverifiable:
		return true
	}
	return false
}

// DriftItem est un écart sur un fichier.
type DriftItem struct {
	StateKey string
	Kind     DriftKind
	Path     string
	Detail   string
}

// DriftReport est le rapport de conformité remonté par un agent (trame 05_15).
type DriftReport struct {
	Scope    Scope
	Username string
	// Checked est le nombre de fichiers vérifiés. Il compte : un rapport sans
	// écart sur zéro fichier vérifié ne dit pas « conforme », il dit « rien
	// n'était inventorié ». Sans ce compte, une machine dont l'inventaire est
	// vide s'afficherait comme parfaitement conforme.
	Checked int
	Items   []DriftItem
}

// Conforming indique qu'aucun écart n'a été constaté.
func (r DriftReport) Conforming() bool { return len(r.Items) == 0 }

// Summary rend le rapport lisible dans un journal.
func (r DriftReport) Summary() string {
	if r.Conforming() {
		return fmt.Sprintf("%d fichier(s) vérifié(s), conforme", r.Checked)
	}
	return fmt.Sprintf("%d fichier(s) vérifié(s), %d écart(s)", r.Checked, len(r.Items))
}
