// Package revocation porte le modèle du kill switch : les modes, les motifs et
// les résultats, avec leur validation.
//
// C'est un paquet FEUILLE : il n'importe rien du projet. La couche base
// (core/database/db_revocation), le transport (ducky-network/revocation_manager),
// le CLI et l'interface web en dépendent tous, sans qu'il dépende d'eux. Un
// mode ou un motif ajouté ici devient valide partout d'un coup, et la couche
// base ne peut pas écrire une valeur que le transport refuserait.
//
// Aucune commande shell ne circule : un ordre dit QUOI faire (verrouiller,
// déverrouiller, supprimer) et sur QUI. C'est l'agent qui décide COMMENT, avec
// les outils de sa distribution. Même principe que les GPO, et pour la même
// raison — un ordre venu du réseau ne doit jamais pouvoir devenir du code
// exécuté en root.
package revocation

import (
	"fmt"
	"strings"
)

// Mode est l'action demandée sur un compte.
type Mode string

const (
	// ModeSoft verrouille : le compte ne peut plus s'authentifier nulle part et
	// perd toutes ses permissions, mais rien n'est détruit. Réversible.
	ModeSoft Mode = "soft"

	// ModeUnlock lève un verrouillage soft.
	ModeUnlock Mode = "unlock"

	// ModeHard supprime : le compte disparaît de l'annuaire et des machines,
	// répertoire personnel compris. Irréversible.
	ModeHard Mode = "hard"
)

// AllModes retourne les modes déclenchables, dans l'ordre de gravité croissante.
func AllModes() []Mode { return []Mode{ModeSoft, ModeUnlock, ModeHard} }

// IsValidMode dit si un mode est connu.
func IsValidMode(m Mode) bool {
	switch m {
	case ModeSoft, ModeUnlock, ModeHard:
		return true
	}
	return false
}

// IsDestructive dit si un mode détruit des données.
//
// Sert à exiger une permission supplémentaire et une confirmation renforcée :
// la frontière n'est pas « soft contre le reste » mais « réversible contre
// irréversible ».
func (m Mode) IsDestructive() bool { return m == ModeHard }

// Label donne une description courte, pour les journaux et l'interface.
func (m Mode) Label() string {
	switch m {
	case ModeSoft:
		return "verrouillage du compte"
	case ModeUnlock:
		return "levée du verrouillage"
	case ModeHard:
		return "suppression définitive du compte"
	}
	return string(m)
}

// Reason est le motif d'une révocation.
//
// Volontairement un code fermé, jamais du texte libre. Le motif circule jusqu'à
// des machines potentiellement compromises : du texte saisi par un
// administrateur n'a rien à y faire, et il finirait dans les journaux de
// l'agent, où il constituerait une surface d'injection. Le détail reste côté
// serveur, dans la trace d'audit.
type Reason string

const (
	// ReasonCompromised : compte compromis, urgence.
	ReasonCompromised Reason = "compromised"
	// ReasonOffboarding : départ d'une personne, procédure normale.
	ReasonOffboarding Reason = "offboarding"
	// ReasonAdminRequest : décision administrative, sans incident.
	ReasonAdminRequest Reason = "admin_request"
)

// AllReasons retourne les motifs acceptés.
func AllReasons() []Reason {
	return []Reason{ReasonCompromised, ReasonOffboarding, ReasonAdminRequest}
}

// IsValidReason dit si un motif est connu.
func IsValidReason(r Reason) bool {
	switch r {
	case ReasonCompromised, ReasonOffboarding, ReasonAdminRequest:
		return true
	}
	return false
}

// Label donne une description courte du motif.
func (r Reason) Label() string {
	switch r {
	case ReasonCompromised:
		return "compte compromis"
	case ReasonOffboarding:
		return "départ de la personne"
	case ReasonAdminRequest:
		return "demande administrative"
	}
	return string(r)
}

// Result est le compte rendu d'un agent pour un ordre.
type Result string

const (
	// ResultApplied : l'ordre a été exécuté.
	ResultApplied Result = "applied"

	// ResultAlreadyAbsent : le compte local n'existe pas sur cette machine.
	//
	// C'est un SUCCÈS, pas une erreur. Un ordre part vers toutes les machines
	// partageant un groupe avec l'utilisateur, or il ne s'est pas forcément
	// connecté à chacune. Traiter ce cas comme un échec provoquerait des
	// réessais sans fin sur des machines qui n'ont rien à faire.
	ResultAlreadyAbsent Result = "already_absent"

	// ResultNotApplicable : l'ordre ne s'applique pas ici (déverrouillage d'un
	// compte qui n'était pas verrouillé, par exemple). Succès également.
	ResultNotApplicable Result = "not_applicable"
)

// Libelle dit le résultat comme on le lit dans un suivi (TO-DO 164).
//
// Les trois sont des succès, et ne se valent pas pour qui cherche où un compte
// travaille encore : « appliqué » dit qu'il y avait quelque chose à couper.
func (r Result) Libelle() string {
	switch r {
	case ResultApplied:
		return "ordre appliqué sur la machine"
	case ResultAlreadyAbsent:
		return "aucun compte local de ce nom sur la machine"
	case ResultNotApplicable:
		return "sans objet sur cette machine"
	}
	return string(r)
}

// IsValidResult dit si un résultat est connu.
func IsValidResult(r Result) bool {
	switch r {
	case ResultApplied, ResultAlreadyAbsent, ResultNotApplicable:
		return true
	}
	return false
}

// TargetStatus est l'état d'un ordre pour une machine donnée.
type TargetStatus string

const (
	// StatusPending : ordre pas encore acquitté. Sera rejoué.
	StatusPending TargetStatus = "pending"
	// StatusAcked : machine ayant confirmé.
	StatusAcked TargetStatus = "acked"
	// StatusFailed : la machine a signalé un échec. Sera rejoué.
	StatusFailed TargetStatus = "failed"
	// StatusLifted : verrouillage LEVÉ avant que cette machine ne l'ait
	// acquitté. Ne sera plus rejoué — TO-DO 49.
	//
	// Un verrouillage et sa levée sont deux ordres. Tant que seul l'agent
	// réclamait ses ordres, au démarrage, ils arrivaient ensemble et dans
	// l'ordre. Mais une machine qui a acquitté la levée et pas le verrouillage
	// — il y avait échoué, des processus refusaient de mourir — gardait ce
	// verrouillage « à rejouer » : rejoué SEUL, il refermait un compte que
	// l'annuaire dit ouvert. La levée range donc ce qu'elle rend sans objet.
	StatusLifted TargetStatus = "lifted"
)

// Libelle dit l'état d'une cible en français — TO-DO 164.
//
// Une seule définition, pour la ligne de commande et le portail. « levé » et
// non « en attente » pour StatusLifted : l'ordre ne sera plus remis, et le
// ranger avec ce qui attend ferait chercher une machine qui n'a rien à faire.
func (s TargetStatus) Libelle() string {
	switch s {
	case StatusPending:
		return "en attente"
	case StatusFailed:
		return "en échec"
	case StatusAcked:
		return "appliqué"
	case StatusLifted:
		return "levé avant application"
	}
	return string(s)
}

// ARejouer dit si une cible dans cet état doit encore recevoir son ordre.
//
// Une seule définition : la requête des ordres en attente, le rejeu du core et
// le décompte « en attente » de l'historique doivent répondre pareil.
func (s TargetStatus) ARejouer() bool {
	return s == StatusPending || s == StatusFailed
}

// Order est un ordre de révocation tel qu'il circule sur le réseau.
type Order struct {
	ID       int
	Mode     Mode
	Username string // forme complète, domaine compris
	Reason   Reason
}

// Validate vérifie qu'un ordre est complet et cohérent.
//
// Appelée à l'écriture ET à la lecture réseau : un ordre lu depuis une trame
// n'est pas plus digne de confiance qu'une saisie d'administrateur.
func (o Order) Validate() error {
	if o.ID <= 0 {
		return fmt.Errorf("identifiant d'ordre invalide")
	}
	if !IsValidMode(o.Mode) {
		return fmt.Errorf("mode inconnu %q", o.Mode)
	}
	if !IsValidReason(o.Reason) {
		return fmt.Errorf("motif inconnu %q", o.Reason)
	}
	if strings.TrimSpace(o.Username) == "" {
		return fmt.Errorf("utilisateur cible manquant")
	}
	// Le nom voyage sur une ligne de trame : un saut de ligne décalerait tout le
	// reste du contenu et ferait lire un champ pour un autre.
	if strings.ContainsAny(o.Username, "\n\r|") {
		return fmt.Errorf("utilisateur cible malformé")
	}
	return nil
}

// Codes d'erreur renvoyés par l'agent dans une trame 06_03.
const (
	ErrUnknownMode      = "unknown_mode"
	ErrCommandFailed    = "command_failed"
	ErrPermissionDenied = "permission_denied"
	ErrInternal         = "internal"
	ErrMalformedOrder   = "malformed_order"
)
