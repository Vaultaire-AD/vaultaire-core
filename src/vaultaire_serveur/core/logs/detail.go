package logs

import (
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"

	"vaultaire/core/storage"
)

// Le détail par sous-système, et le niveau TRACE — TO-DO 145.
//
// # Ce que ce fichier corrige
//
// Le mode debug était UN booléen pour tout le serveur. L'allumer pour suivre
// une GPO ouvrait aussi le robinet de l'annuaire : un client comme Keycloak
// lance plusieurs recherches par connexion d'utilisateur, et chacune écrivait
// une ligne par étape, par entrée et par nœud de filtre. Le reste du journal
// disparaissait dessous.
//
// Deux réglages remplacent le booléen, sans le retirer :
//
//   - le détail se règle PAR SOUS-SYSTÈME — `ldap`, `ducky`, `gpo`, `base` —,
//     en plus ou en moins du réglage général : debug partout sauf l'annuaire,
//     ou l'annuaire seul sur un serveur silencieux ;
//   - un niveau TRACE passe SOUS le DEBUG. Le DEBUG d'un sous-système dit ce
//     qui s'est passé, une ligne par opération ; le TRACE déroule le comment,
//     étape par étape. Il ne s'allume jamais avec le réglage général : il se
//     demande nommément, pour un sous-système.
//
// # Le sous-système est celui du CODE qui écrit la ligne
//
// Il n'est pas passé en argument : il est déduit du fichier de l'appelant. Le
// serveur porte environ 130 appels DEBUG, dans une quarantaine de dossiers ;
// leur faire porter chacun une étiquette aurait demandé de tous les réécrire,
// et le suivant aurait été écrit sans. Rangé par dossier, un appel ajouté
// demain dans `core/ldap` est une ligne de l'annuaire sans que personne y
// pense — et une ligne écrite par `core/permission` pendant un bind reste une
// ligne des permissions, ce qui est exact : c'est ce code-là qui parle.
//
// Le coût est un `runtime.Caller` par ligne DEBUG ou TRACE. Il n'est payé que
// si un réglage par sous-système existe ; sans aucun, le chemin est celui de
// toujours — un booléen lu, et rien d'autre.

// SousSysteme nomme une partie du serveur dont le détail se règle à part.
type SousSysteme string

const (
	// SousLDAP : l'annuaire — core/ldap et ses lectures en base.
	SousLDAP SousSysteme = "ldap"
	// SousDucky : le canal des agents, des proxys et des services.
	SousDucky SousSysteme = "ducky"
	// SousGPO : la résolution, la signature et le transport des politiques.
	SousGPO SousSysteme = "gpo"
	// SousBase : la couche d'accès à la base de données.
	SousBase SousSysteme = "base"
)

// Detail est ce qu'un sous-système écrit en dessous d'INFO.
type Detail int32

const (
	// DetailCoupe : rien sous INFO.
	DetailCoupe Detail = iota
	// DetailDebug : les lignes DEBUG.
	DetailDebug
	// DetailTrace : DEBUG et TRACE.
	DetailTrace
)

// detailHerite : le sous-système n'a pas de réglage propre, il suit `debug`.
const detailHerite = int32(-1)

// String rend le mot employé dans la configuration et sur la ligne de commande.
func (d Detail) String() string {
	switch d {
	case DetailTrace:
		return "trace"
	case DetailDebug:
		return "debug"
	default:
		return "off"
	}
}

// rangement dit à quel sous-système appartient un fichier source.
//
// L'ORDRE COMPTE : le premier motif présent dans le chemin gagne, donc le plus
// précis d'abord. `db_ldap` et `db_gpo` vivent sous `core/database` et doivent
// être rangés avec l'annuaire et les politiques — ce sont leurs requêtes —, et
// `gpo_manager` vit sous `ducky-network` sans être du transport.
//
// Les motifs commencent et finissent par « / » : ils désignent des DOSSIERS, et
// tiennent aussi bien sur un chemin absolu que sur le chemin d'un binaire
// compilé avec -trimpath (`vaultaire/core/ldap/…`).
//
// Un dossier renommé perdrait son rangement en silence : ses lignes suivraient
// le réglage général, sans erreur. `TestLeRangementDesigneDesDossiersQuiExistent`
// échoue dans ce cas.
var rangement = []struct {
	motif string
	sous  SousSysteme
}{
	{"/core/ldap/", SousLDAP},
	{"/core/database/db_ldap/", SousLDAP},
	{"/ducky-network/gpo_manager/", SousGPO},
	{"/core/gpo/", SousGPO},
	{"/core/database/db_gpo/", SousGPO},
	{"/ducky-network/", SousDucky},
	{"/core/database/", SousBase},
}

// ordreDesSousSystemes est l'ordre d'affichage, et la liste de ce qui se règle.
var ordreDesSousSystemes = []SousSysteme{SousLDAP, SousDucky, SousGPO, SousBase}

// reglagesDeDetail porte le réglage propre de chaque sous-système.
//
// Des atomiques, parce que ces valeurs sont lues à chaque ligne DEBUG depuis
// n'importe quelle goroutine et écrites par une commande d'administration. La
// table elle-même n'est jamais modifiée après l'initialisation du paquet : la
// lire sans verrou est sûr.
var reglagesDeDetail = func() map[SousSysteme]*atomic.Int32 {
	table := make(map[SousSysteme]*atomic.Int32, len(ordreDesSousSystemes))
	for _, s := range ordreDesSousSystemes {
		v := new(atomic.Int32)
		v.Store(detailHerite)
		table[s] = v
	}
	return table
}()

// reglagesPoses compte les sous-systèmes qui portent un réglage propre. À
// zéro, aucune ligne ne paie la recherche de son appelant.
var reglagesPoses atomic.Int32

// SousSystemes rend les sous-systèmes réglables, dans l'ordre d'affichage.
func SousSystemes() []SousSysteme {
	return append([]SousSysteme(nil), ordreDesSousSystemes...)
}

// SousSystemeNomme reconnaît un nom saisi — configuration, commande, formulaire.
func SousSystemeNomme(nom string) (SousSysteme, bool) {
	s := SousSysteme(strings.ToLower(strings.TrimSpace(nom)))
	_, connu := reglagesDeDetail[s]
	return s, connu
}

// NomsDesSousSystemes rend la liste pour un message : « ldap, ducky, gpo, base ».
func NomsDesSousSystemes() string {
	noms := make([]string, len(ordreDesSousSystemes))
	for i, s := range ordreDesSousSystemes {
		noms[i] = string(s)
	}
	return strings.Join(noms, ", ")
}

// LireDetail analyse un niveau de détail saisi.
//
// `herite` vaut vrai pour « defaut » : le sous-système n'a plus de réglage
// propre et suit de nouveau `debug`. C'est une valeur à part entière, et non
// l'absence de valeur : il faut pouvoir RETIRER un réglage sans redémarrer.
//
// Une saisie inconnue est une ERREUR, jamais un « off » par défaut : une faute
// de frappe couperait le détail en laissant croire que rien n'a changé — le
// défaut que `update -debug` avait déjà eu avec « ture ».
func LireDetail(texte string) (d Detail, herite bool, err error) {
	switch strings.ToLower(strings.TrimSpace(texte)) {
	case "off", "false", "non", "0":
		return DetailCoupe, false, nil
	case "debug", "on", "true", "oui", "1":
		return DetailDebug, false, nil
	case "trace":
		return DetailTrace, false, nil
	case "defaut", "défaut", "default", "herite", "hérite":
		return DetailCoupe, true, nil
	}
	return DetailCoupe, false, fmt.Errorf(
		"niveau de détail %q invalide : attendu off, debug, trace ou defaut", texte)
}

// ReglerDetail pose le réglage propre d'un sous-système.
func ReglerDetail(s SousSysteme, d Detail) {
	v, connu := reglagesDeDetail[s]
	if !connu {
		return
	}
	if d < DetailCoupe || d > DetailTrace {
		d = DetailCoupe
	}
	if v.Swap(int32(d)) == detailHerite {
		reglagesPoses.Add(1)
	}
}

// LaisserDetail retire le réglage propre : le sous-système suit `debug`.
func LaisserDetail(s SousSysteme) {
	v, connu := reglagesDeDetail[s]
	if !connu {
		return
	}
	if v.Swap(detailHerite) != detailHerite {
		reglagesPoses.Add(-1)
	}
}

// DetailRegle rend le réglage PROPRE d'un sous-système, et false s'il n'en a
// pas. Pour l'affichage : « ldap : trace » ne se lit pas comme « ldap : suit
// debug », même quand les deux écrivent la même chose.
func DetailRegle(s SousSysteme) (Detail, bool) {
	v, connu := reglagesDeDetail[s]
	if !connu {
		return DetailCoupe, false
	}
	brut := v.Load()
	if brut == detailHerite {
		return DetailCoupe, false
	}
	return Detail(brut), true
}

// DetailDe rend le détail EFFECTIF d'un sous-système : son réglage propre s'il
// en a un, sinon ce que donne `debug`.
//
// Un sous-système inconnu — le nom vide, celui du code qui n'est rangé nulle
// part — suit `debug`, et n'a donc jamais de TRACE.
func DetailDe(s SousSysteme) Detail {
	if v, connu := reglagesDeDetail[s]; connu {
		if brut := v.Load(); brut != detailHerite {
			return Detail(brut)
		}
	}
	if storage.Debug {
		return DetailDebug
	}
	return DetailCoupe
}

// DebugActif dit si le sous-système écrit ses lignes DEBUG.
//
// Sert de GARDE autour d'un message coûteux à construire : `Write_Log` écarte
// la ligne, mais après que l'appelant a formaté son texte. Sur le chemin d'une
// recherche LDAP, cela faisait un `Sprintf` par entrée pour rien.
func DebugActif(s SousSysteme) bool { return DetailDe(s) >= DetailDebug }

// TraceActive dit si le sous-système écrit ses lignes TRACE.
func TraceActive(s SousSysteme) bool { return DetailDe(s) >= DetailTrace }

// UnDetailEstActif dit si quoi que ce soit s'écrit sous INFO, où que ce soit.
//
// C'est la question de l'avertissement de démarrage : le détail porte la
// cartographie de l'annuaire et des droits, qu'il vienne de `debug: true` ou
// d'un seul sous-système.
func UnDetailEstActif() bool {
	if storage.Debug {
		return true
	}
	for _, s := range ordreDesSousSystemes {
		if DetailDe(s) > DetailCoupe {
			return true
		}
	}
	return false
}

// EtatDuDetail rend l'état complet en une ligne, pour une réponse de commande :
//
//	debug=false ; ldap=trace, ducky=(suit debug), gpo=(suit debug), base=off
func EtatDuDetail() string {
	parties := make([]string, len(ordreDesSousSystemes))
	for i, s := range ordreDesSousSystemes {
		if d, propre := DetailRegle(s); propre {
			parties[i] = string(s) + "=" + d.String()
		} else {
			parties[i] = string(s) + "=(suit debug)"
		}
	}
	return fmt.Sprintf("debug=%v ; %s", storage.Debug, strings.Join(parties, ", "))
}

// rangSousInfo classe un niveau : 0 s'il est émis sans condition, 1 pour
// DEBUG, 2 pour TRACE.
func rangSousInfo(level string) Detail {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return DetailDebug
	case "TRACE":
		return DetailTrace
	}
	return DetailCoupe
}

// emissionPermise dit si une ligne de ce niveau doit sortir.
//
// `saut` est le nombre de cadres entre cette fonction et le code qui a écrit
// la ligne : 2 quand elle est appelée par `Write_Log` et ses sœurs.
func emissionPermise(level string, saut int) bool {
	rang := rangSousInfo(level)
	if rang == DetailCoupe {
		return true
	}
	if reglagesPoses.Load() == 0 {
		// Le chemin de toujours : aucun réglage par sous-système, le booléen
		// décide — et il n'a jamais donné de TRACE.
		return rang == DetailDebug && storage.Debug
	}
	return DetailDe(sousSystemeAppelant(saut+1)) >= rang
}

// sousSystemeAppelant range le code qui se trouve `saut` cadres au-dessus.
func sousSystemeAppelant(saut int) SousSysteme {
	_, fichier, _, ok := runtime.Caller(saut)
	if !ok {
		return ""
	}
	return SousSystemeDuFichier(fichier)
}

// SousSystemeDuFichier range un chemin de fichier source. Rend le nom vide
// pour ce qui n'appartient à aucun sous-système réglable.
func SousSystemeDuFichier(fichier string) SousSysteme {
	// Un binaire compilé sous Windows porte des « \ » ; un chemin -trimpath
	// commence par le nom du module, sans « / » devant.
	chemin := "/" + strings.ReplaceAll(fichier, `\`, "/")
	for _, r := range rangement {
		if strings.Contains(chemin, r.motif) {
			return r.sous
		}
	}
	return ""
}

// MotifsDeRangement rend les dossiers rangés, pour le test qui vérifie qu'ils
// existent.
func MotifsDeRangement() map[string]SousSysteme {
	out := make(map[string]SousSysteme, len(rangement))
	for _, r := range rangement {
		out[r.motif] = r.sous
	}
	return out
}
