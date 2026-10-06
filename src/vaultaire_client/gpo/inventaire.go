package gpo

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"sync"
)

// Inventaire de travail d'UN cycle — TO-DO 135.
//
// # Ce qu'il y avait
//
// Une seule carte, globale au paquet, où `writeSystemFile` notait ce qu'il
// venait d'écrire. `applyModule` la relevait avant d'appeler un appliqueur,
// puis demandait ce qui avait bougé : c'était l'attribution d'un fichier au
// module qui l'a déposé.
//
// Trois choses n'allaient pas, et aucune ne se voyait tant que seul le scope
// machine y écrivait :
//
//   - elle n'était JAMAIS vidée. Son commentaire disait « vidée au début de
//     chaque cycle par ResetManifest » ; ResetManifest n'avait aucun appelant
//     hors des tests. Un fichier réécrit à l'identique ne ressortait donc pas
//     comme « apparu », et son entrée restait celle d'un cycle antérieur ;
//   - l'attribution comparait des CONTENUS. Deux modules qui écrivent le même
//     fichier avec le même contenu — toutes les variables d'environnement d'un
//     compte vivent dans un seul `.vaultaire_env` — ne laissaient que le premier
//     comme propriétaire ;
//   - elle était PARTAGÉE entre des cycles qui tournent en même temps. Le cycle
//     machine a sa boucle, chaque compte a le sien, déclenché par PAM : deux
//     personnes qui ouvrent une session à la même seconde relevaient la même
//     carte, et le fichier de l'une pouvait être attribué au module de l'autre.
//
// Le troisième point était sans conséquence tant que le scope utilisateur
// n'inscrivait rien — c'est justement le défaut du 135. L'y faire inscrire sans
// séparer les cycles aurait remplacé une conformité muette par une conformité
// fausse : un `HOME` vérifié contre les fichiers d'un autre compte.
//
// # Ce qu'il y a maintenant
//
// Un inventaire PAR CYCLE. Celui de la machine est unique et vidé au début de
// chaque application — un seul cycle machine tourne à la fois. Celui d'un
// compte est créé pour l'application et jeté avec elle. Chacun n'est écrit que
// par son propre cycle : il n'y a plus rien à démêler.
//
// # Un rang plutôt qu'une comparaison
//
// Chaque inscription reçoit un rang croissant. « Ce que ce module a écrit » se
// lit alors « ce qui porte un rang postérieur à sa marque de départ », sans
// regarder le contenu : une réécriture à l'identique EST une écriture, et le
// module qui l'a faite en répond comme un autre.
type inventaire struct {
	mu   sync.Mutex
	rang int

	fichiers map[string]fichierNote
	attentes map[string]attenteNotee
}

type fichierNote struct {
	etat FileState
	rang int
}

type attenteNotee struct {
	attente SystemCheck
	rang    int
}

func nouvelInventaire() *inventaire {
	return &inventaire{
		fichiers: map[string]fichierNote{},
		attentes: map[string]attenteNotee{},
	}
}

// inventaireMachine est l'inventaire du cycle MACHINE.
//
// Unique, parce que le cycle machine l'est (`machineActive`), et global parce
// que les appliqueurs du scope machine écrivent par `writeSystemFile(chemin, …)`
// sans rien recevoir du cycle : leur faire porter un contexte aurait demandé de
// retoucher les trente-quatre.
//
// Un appliqueur qui connaît le scope UTILISATEUR ne doit jamais y écrire — il
// passe par les formes qui prennent le contexte. Un test-sentinelle le garde,
// voir sentinelle_inventaire_test.go.
var inventaireMachine = nouvelInventaire()

// vider remet l'inventaire à neuf.
func (i *inventaire) vider() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rang = 0
	i.fichiers = map[string]fichierNote{}
	i.attentes = map[string]attenteNotee{}
}

// marque rend le rang de la dernière inscription.
//
// `applyModule` la relève avant d'appeler l'appliqueur : tout ce qui portera un
// rang supérieur appartient au module qu'il vient d'appliquer.
func (i *inventaire) marque() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.rang
}

// noterEcriture inscrit un fichier déposé EN ENTIER par la politique.
//
// Le hachage est celui du contenu demandé, pas une relecture du disque : c'est
// ce que la politique veut, et c'est à cela que le scan comparera.
func (i *inventaire) noterEcriture(chemin, contenu string, mode os.FileMode) {
	somme := sha256.Sum256([]byte(contenu))
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rang++
	i.fichiers[chemin] = fichierNote{
		etat: FileState{SHA256: hex.EncodeToString(somme[:]), Mode: uint32(mode.Perm())},
		rang: i.rang,
	}
}

// noterAbsence inscrit un fichier que la politique RETIRE.
//
// Écrase une écriture antérieure du même cycle, et l'inverse : la dernière
// opération décrit l'état où le système a été laissé.
func (i *inventaire) noterAbsence(chemin string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rang++
	i.fichiers[chemin] = fichierNote{etat: FileState{Absent: true}, rang: i.rang}
}

// noterAttente inscrit un état à revérifier.
func (i *inventaire) noterAttente(kind, target, expect string) {
	c := SystemCheck{Kind: kind, Target: target, Expect: expect}
	i.mu.Lock()
	defer i.mu.Unlock()
	i.rang++
	i.attentes[c.CheckID()] = attenteNotee{attente: c, rang: i.rang}
}

// fichiersDepuis rend ce qui a été inscrit après une marque, attribué.
func (i *inventaire) fichiersDepuis(marque int, stateKey string) map[string]FileState {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := map[string]FileState{}
	for chemin, note := range i.fichiers {
		if note.rang <= marque {
			continue
		}
		etat := note.etat
		etat.StateKey = stateKey
		out[chemin] = etat
	}
	return out
}

// attentesDepuis rend les attentes inscrites après une marque, attribuées.
func (i *inventaire) attentesDepuis(marque int, stateKey string) map[string]SystemCheck {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := map[string]SystemCheck{}
	for id, note := range i.attentes {
		if note.rang <= marque {
			continue
		}
		c := note.attente
		c.StateKey = stateKey
		out[id] = c
	}
	return out
}

// releveFichiers rend une copie de ce qui est inscrit, pour un test ou un
// diagnostic. Le moteur, lui, n'attribue que par les marques.
func (i *inventaire) releveFichiers() map[string]FileState {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make(map[string]FileState, len(i.fichiers))
	for chemin, note := range i.fichiers {
		out[chemin] = note.etat
	}
	return out
}

// releveAttentes est le pendant de releveFichiers.
func (i *inventaire) releveAttentes() map[string]SystemCheck {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make(map[string]SystemCheck, len(i.attentes))
	for id, note := range i.attentes {
		out[id] = note.attente
	}
	return out
}

// --- qui répond d'un fichier -------------------------------------------------

// proprietaires rend les modules qui répondent d'un fichier.
//
// Un seul dans le cas courant : `StateKey`. Plusieurs quand des modules
// distincts écrivent le MÊME fichier — voir FileState.Owners.
func (f FileState) proprietaires() []string {
	if len(f.Owners) > 0 {
		return f.Owners
	}
	if f.StateKey == "" {
		return nil
	}
	return []string{f.StateKey}
}

// sansProprietaire retire un module des propriétaires d'un fichier.
//
// Rend faux quand il n'en reste aucun : l'entrée n'a plus de raison d'être.
func (f FileState) sansProprietaire(stateKey string) (FileState, bool) {
	restants := make([]string, 0, len(f.Owners))
	for _, key := range f.proprietaires() {
		if key != stateKey {
			restants = append(restants, key)
		}
	}
	return f.avecProprietaires(restants)
}

// avecProprietaires pose la liste, dans sa forme canonique.
//
// `Owners` n'est écrit que s'il y a PLUSIEURS propriétaires : le cas courant
// garde exactement la forme d'avant, lisible par un agent antérieur. `StateKey`
// reste renseigné dans tous les cas — c'est le champ qu'un agent ancien lit, et
// celui qui part dans le rapport 05_15.
func (f FileState) avecProprietaires(keys []string) (FileState, bool) {
	uniques := map[string]struct{}{}
	var liste []string
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, deja := uniques[key]; deja {
			continue
		}
		uniques[key] = struct{}{}
		liste = append(liste, key)
	}
	if len(liste) == 0 {
		return f, false
	}
	sort.Strings(liste)

	// Le dernier module à avoir écrit reste en tête d'affiche s'il est encore
	// là ; sinon le premier des restants, pour que le champ ne désigne jamais
	// un module disparu.
	if _, encore := uniques[f.StateKey]; !encore {
		f.StateKey = liste[0]
	}
	if len(liste) == 1 {
		f.Owners = nil
	} else {
		f.Owners = liste
	}
	return f, true
}
