package gpo

import "fmt"

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
)

// IsValidDriftKind indique si un type d'écart est reconnu.
//
// Fail-closed comme partout ailleurs : un agent qui inventerait un type verrait
// sa ligne écartée, pas enregistrée sous une valeur que rien n'interprète.
func IsValidDriftKind(k string) bool {
	switch DriftKind(k) {
	case DriftModified, DriftMissing, DriftUnreadable, DriftPermissions:
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
