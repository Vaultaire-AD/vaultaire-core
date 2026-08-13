// Package reglages rassemble les durées d'exploitation du serveur.
//
// # Le problème
//
// Les périodes des boucles étaient dispersées : une dans le fichier YAML
// (`servercheckonlinetimer`), les autres écrites en dur dans le `time.NewTicker`
// de chaque boucle. Changer la cadence du balayage du cluster demandait de
// modifier le code et de recompiler ; changer celle de la vérification en ligne
// demandait d'éditer un fichier et de redémarrer.
//
// Deux mécanismes pour la même question, aucun consultable, et rien qui dise
// quelles durées existent.
//
// # Ce que ce paquet établit
//
//	le DÉFAUT est en Go, la valeur COURANTE est en base, et la base l'emporte.
//
// Le défaut en Go plutôt qu'en base : une base neuve, vide ou injoignable doit
// donner un serveur qui tourne. Un défaut en base serait une ligne à insérer à
// la création, donc une migration à écrire, et une installation qui l'aurait
// manquée démarrerait avec des périodes nulles.
//
// La base plutôt que le fichier : le fichier impose un redémarrage, et un
// redémarrage de core coupe le parc. Un réglage de cadence ne vaut pas ça.
//
// # Ce qui n'est PAS ici, et pourquoi
//
// Les délais de PROTOCOLE et de SÉCURITÉ restent des constantes du code :
// échéances de lecture réseau (`netguard`), fenêtre anti-rejeu de l'API, durée
// de vie d'un défi d'authentification, barème de la limitation de débit.
//
// Ce ne sont pas des préférences d'exploitation mais des propriétés du
// protocole : une échéance de poignée de main trop longue ouvre un déni de
// service, trop courte casse les connexions lentes. Les exposer inviterait à les
// régler sans savoir ce qu'on règle, et le symptôme d'un mauvais choix
// apparaîtrait ailleurs, longtemps après.
//
// Les durées de l'AGENT non plus : elles vivent sur la machine du parc et n'ont
// aucun moyen d'être lues depuis le core. Elles relèvent des GPO.
package reglages

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"vaultaire/core/database"
	dbsettings "vaultaire/core/database/db_settings"
)

// Unite dit en quoi la valeur d'un réglage est exprimée.
//
// Stockée en base comme un ENTIER dans cette unité, et non en secondes pour
// tout le monde : « 24 » heures se lit et se saisit, « 86400 » se recopie de
// travers. L'unité est celle dans laquelle un exploitant pense au réglage.
type Unite string

const (
	Secondes Unite = "s"
	Minutes  Unite = "min"
	Heures   Unite = "h"
)

// Duree convertit une valeur entière dans son unité.
func (u Unite) Duree(v int) time.Duration {
	switch u {
	case Secondes:
		return time.Duration(v) * time.Second
	case Minutes:
		return time.Duration(v) * time.Minute
	case Heures:
		return time.Duration(v) * time.Hour
	}
	return 0
}

// Definition décrit un réglage de durée.
type Definition struct {
	// Cle identifie le réglage en base et en ligne de commande.
	Cle string

	// Libelle dit ce que la durée gouverne, en une ligne.
	Libelle string

	// Unite, Defaut, Min, Max bornent la saisie.
	//
	// Les bornes ne sont pas des limites de sécurité mais des garde-fous de
	// saisie : une valeur absurde — un horodatage collé dans le champ — mettrait
	// une boucle en sommeil pour des années sans le dire, alors qu'un refus
	// explicite se voit.
	Unite  Unite
	Defaut int
	Min    int
	Max    int

	// Consequence explique ce que change une valeur trop basse ou trop haute.
	// Affichée à côté du réglage : qui règle une cadence sans savoir ce qu'elle
	// coûte choisit au hasard.
	Consequence string
}

// Les clés, nommées plutôt qu'écrites en littéral aux points d'usage.
const (
	CleVerificationEnLigne = "check_online_minutes"
	CleSessionsDucky       = "ducky_session_purge_minutes"
	CleBattementCluster    = "cluster_heartbeat_seconds"
	CleNettoyageCluster    = "cluster_cleanup_seconds"
	CleBalayageServices    = "service_sweep_seconds"
	CleSessionWeb          = "web_session_minutes"
	CleSessionWebPurge     = "web_session_purge_minutes"
	CleSynchroGroupes      = "group_sync_minutes"
)

// catalogue déclare toutes les durées réglables.
//
// L'ordre est celui de l'affichage : du plus visible à l'exploitation au plus
// interne.
var catalogue = []Definition{
	{
		Cle: CleVerificationEnLigne, Unite: Minutes, Defaut: 2, Min: 1, Max: 60,
		Libelle: "Vérification des machines en ligne",
		Consequence: "Le core envoie un 02_11 à chaque machine à cette cadence. " +
			"Plus court : une machine tombée est vue plus vite, au prix d'un " +
			"réveil de tout le parc. Plus long : l'annuaire affiche en ligne des " +
			"postes éteints.",
	},
	{
		Cle: CleSessionsDucky, Unite: Minutes, Defaut: 5, Min: 1, Max: 120,
		Libelle: "Purge des sessions Ducky expirées",
		Consequence: "Entre deux passages, une session expirée occupe encore un " +
			"descripteur et une entrée de registre. Allonger économise peu et " +
			"retarde la libération.",
	},
	{
		Cle: CleBattementCluster, Unite: Secondes, Defaut: 30, Min: 5, Max: 600,
		Libelle: "Battement de cœur du nœud vers le cluster",
		Consequence: "Doit rester NETTEMENT inférieur au seuil de péremption, " +
			"sinon un nœud parfaitement vivant est déclaré hors ligne entre deux " +
			"battements.",
	},
	{
		Cle: CleNettoyageCluster, Unite: Secondes, Defaut: 30, Min: 5, Max: 3600,
		Libelle: "Mise hors ligne des nœuds silencieux",
		Consequence: "Cadence à laquelle le core relit les battements et marque " +
			"hors ligne ceux qui manquent.",
	},
	{
		Cle: CleBalayageServices, Unite: Secondes, Defaut: 60, Min: 10, Max: 3600,
		Libelle: "Balayage des services hors ligne",
		Consequence: "Doit rester INFÉRIEUR au seuil de péremption d'un battement, " +
			"sinon un service tombé reste affiché en ligne pendant près de deux " +
			"fois ce seuil.",
	},
	{
		Cle: CleSessionWeb, Unite: Minutes, Defaut: 30, Min: 5, Max: 1440,
		Libelle: "Durée d'une session du portail web",
		Consequence: "C'est la fenêtre pendant laquelle un jeton volé reste " +
			"utilisable. Allonger le confort allonge exactement cela.",
	},
	{
		Cle: CleSessionWebPurge, Unite: Minutes, Defaut: 5, Min: 1, Max: 120,
		Libelle: "Purge des sessions web expirées",
		Consequence: "N'affecte pas la validité d'une session — elle expire à " +
			"l'heure dite — seulement le moment où son entrée quitte la mémoire.",
	},
	{
		Cle: CleSynchroGroupes, Unite: Minutes, Defaut: 60, Min: 5, Max: 1440,
		Libelle: "Synchronisation des groupes du domaine sur les machines",
		Consequence: "Cadence à laquelle chaque machine redemande la liste des " +
			"groupes de ses domaines. C'est le délai maximal pendant lequel un " +
			"groupe supprimé garde ses membres sur un poste — donc pendant lequel " +
			"les droits qu'il donne restent effectifs. Ce réglage est le seul du " +
			"catalogue qui pilote une boucle du PARC et non du core : sa valeur " +
			"part dans la trame 03_09, et une machine hors ligne l'applique au " +
			"retour, pas avant.",
	},
}

// index permet la recherche par clé sans parcourir le catalogue.
var index = func() map[string]Definition {
	m := make(map[string]Definition, len(catalogue))
	for _, d := range catalogue {
		m[d.Cle] = d
	}
	return m
}()

// Catalogue rend les définitions, dans l'ordre d'affichage.
func Catalogue() []Definition {
	out := make([]Definition, len(catalogue))
	copy(out, catalogue)
	return out
}

// DefinitionDe rend la déclaration d'une clé.
func DefinitionDe(cle string) (Definition, bool) {
	d, ok := index[cle]
	return d, ok
}

// --- lecture, avec cache -----------------------------------------------------

// dureeDuCache borne la fraîcheur d'une valeur lue.
//
// # Pourquoi un cache
//
// Les boucles relisent leur période à CHAQUE tour, pour qu'un changement prenne
// effet sans redémarrage. Sans cache, la boucle de battement du cluster
// interrogerait la base toutes les trente secondes, pour un réglage qui change
// une fois par an.
//
// # Pourquoi il est court
//
// Trente secondes : un exploitant qui modifie un réglage veut le voir agir, pas
// se demander s'il a mal saisi. Un cache long transformerait « ça ne marche
// pas » en « attendez ». C'est la même valeur que le cache de la politique de
// mot de passe, pour ne pas avoir deux fraîcheurs différentes à expliquer.
const dureeDuCache = 30 * time.Second

type valeurEnCache struct {
	valeur int
	lue    time.Time
}

var (
	cacheMu sync.RWMutex
	cache   = map[string]valeurEnCache{}
)

// maintenant est remplaçable par les tests.
var maintenant = time.Now

// lireEnBase est remplaçable par les tests : sans cela, éprouver la résolution
// demanderait une base vivante — et `database.GetDatabase()` rend nil sans elle,
// donc l'appel paniquerait et emporterait le binaire de test du paquet.
var lireEnBase = func(cle string, min, max, def int) int {
	return dbsettings.GetInt(database.GetDatabase(), cle, min, max, def)
}

// Valeur rend la valeur courante d'un réglage, dans son unité.
//
// Une clé inconnue rend zéro : c'est une faute de programmation, pas une
// condition d'exécution, et la boucle qui l'emploierait s'arrêterait aussitôt
// plutôt que de tourner à une cadence inventée.
func Valeur(cle string) int {
	d, ok := index[cle]
	if !ok {
		return 0
	}

	cacheMu.RLock()
	c, present := cache[cle]
	cacheMu.RUnlock()
	if present && maintenant().Sub(c.lue) < dureeDuCache {
		return c.valeur
	}

	v := lireEnBase(cle, d.Min, d.Max, d.Defaut)

	cacheMu.Lock()
	cache[cle] = valeurEnCache{valeur: v, lue: maintenant()}
	cacheMu.Unlock()
	return v
}

// Duree rend la valeur courante convertie.
//
// C'est la fonction que les boucles emploient : elles n'ont pas à savoir dans
// quelle unité le réglage est exprimé.
func Duree(cle string) time.Duration {
	d, ok := index[cle]
	if !ok {
		return 0
	}
	return d.Unite.Duree(Valeur(cle))
}

// --- écriture ----------------------------------------------------------------

// ecrireEnBase est remplaçable par les tests.
var ecrireEnBase = func(cle string, valeur, min, max int, par string) error {
	return dbsettings.SetInt(database.GetDatabase(), cle, valeur, min, max, par)
}

// Ecrire enregistre une valeur et invalide le cache.
//
// L'invalidation est immédiate et locale. Sur un cluster, les AUTRES cores
// gardent leur valeur jusqu'à l'expiration de leur propre cache : trente
// secondes de désaccord, sur un réglage de cadence, sans conséquence.
func Ecrire(cle string, valeur int, par string) error {
	d, ok := index[cle]
	if !ok {
		return fmt.Errorf("réglage %q inconnu — voir « vlt settings list »", cle)
	}
	if valeur < d.Min || valeur > d.Max {
		return fmt.Errorf("%s doit être compris entre %d et %d %s",
			d.Cle, d.Min, d.Max, d.Unite)
	}
	if err := ecrireEnBase(cle, valeur, d.Min, d.Max, par); err != nil {
		return err
	}
	oublier(cle)
	return nil
}

// Reinitialiser ramène un réglage à son défaut codé.
//
// Écrit le défaut plutôt que de supprimer la ligne : une ligne supprimée et un
// défaut écrit se lisent pareil aujourd'hui, mais la ligne porte `updated_by` —
// et savoir QUI a remis un réglage au défaut est exactement ce qu'on cherchera
// si une cadence change sans explication.
func Reinitialiser(cle string, par string) error {
	d, ok := index[cle]
	if !ok {
		return fmt.Errorf("réglage %q inconnu", cle)
	}
	return Ecrire(cle, d.Defaut, par)
}

// oublier retire une entrée du cache.
func oublier(cle string) {
	cacheMu.Lock()
	delete(cache, cle)
	cacheMu.Unlock()
}

// OublierTout vide le cache. Réservé aux tests et au rechargement manuel.
func OublierTout() {
	cacheMu.Lock()
	cache = map[string]valeurEnCache{}
	cacheMu.Unlock()
}

// --- affichage ---------------------------------------------------------------

// Etat décrit un réglage et sa valeur courante, pour les façades.
type Etat struct {
	Definition
	Valeur    int
	AuDefaut  bool
	Affichage string
}

// EtatCourant rend l'état de tous les réglages.
func EtatCourant() []Etat {
	out := make([]Etat, 0, len(catalogue))
	for _, d := range catalogue {
		v := Valeur(d.Cle)
		out = append(out, Etat{
			Definition: d,
			Valeur:     v,
			AuDefaut:   v == d.Defaut,
			Affichage:  fmt.Sprintf("%d %s", v, d.Unite),
		})
	}
	return out
}

// Cles rend les clés connues, triées. Sert aux messages d'erreur et à
// l'autocomplétion.
func Cles() string {
	noms := make([]string, 0, len(catalogue))
	for _, d := range catalogue {
		noms = append(noms, d.Cle)
	}
	sort.Strings(noms)
	return strings.Join(noms, ", ")
}
