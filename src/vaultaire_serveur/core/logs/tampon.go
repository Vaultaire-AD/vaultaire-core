package logs

import (
	"os"
	"sync"
)

// Le tampon mémoire du journal — TO-DO 154.
//
// # À quoi il sert
//
// Les journaux se lisent en base, tous cores confondus. La mémoire est le
// REPLI de « vlt logs » quand la base ne répond pas — c'est-à-dire au moment
// précis où l'on a le plus besoin de lire un journal. Elle garde les
// CapaciteDuTampon dernières lignes de CE core.
//
// # Le défaut
//
// Les entrées vivaient dans une tranche qu'on allongeait, puis qu'on
// retaillait dès qu'elle dépassait la capacité :
//
//	keep := b.entries[len(b.entries)-b.maxSize:]
//	b.entries = make([]LogEntry, len(keep), b.maxSize)
//	copy(b.entries, keep)
//
// La tranche neuve était allouée PLEINE : la ligne suivante la faisait
// déborder de nouveau. Une fois les dix mille lignes atteintes — une fois pour
// toutes, quelques heures après le démarrage —, CHAQUE ligne de journal
// allouait trois mégaoctets et y recopiait dix mille entrées, sous le verrou,
// donc en série pour tout ce qui journalise. Mesuré : 3,5 ms par ligne, contre
// 0,1 µs avant le plein. Un core ne pouvait plus écrire que trois cents lignes
// par seconde, et un bind LDAP en écrit deux.
//
// # La forme
//
// Un anneau : la tranche grandit jusqu'à la capacité, puis n'est plus jamais
// réallouée. Une ligne de plus écrase la plus ancienne, et un indice dit où
// elle se trouve. Ajouter coûte une affectation ; l'ordre se reconstitue à la
// LECTURE, qui est rare.
//
// La tranche grandit plutôt que d'être allouée entière d'emblée : un core qui
// n'écrit que cent lignes ne garde pas dix mille entrées vides.

// CapaciteDuTampon est le nombre de lignes gardées en mémoire.
const CapaciteDuTampon = 10000

// LogBuffer garde en mémoire les dernières lignes du journal.
type LogBuffer struct {
	mu sync.RWMutex

	// entries porte les lignes. Tant que le tampon n'est pas plein, elles y
	// sont dans l'ordre d'arrivée. Une fois plein, la plus ancienne est à
	// l'indice `plusAncienne`, et l'ordre fait le tour.
	entries []LogEntry
	// plusAncienne n'a de sens que tampon plein : c'est la case que la
	// prochaine ligne écrasera.
	plusAncienne int

	maxSize  int
	hostname string
}

var (
	globalBuffer *LogBuffer
	bufferOnce   sync.Once
)

// nouveauTampon prépare un tampon d'une capacité donnée.
func nouveauTampon(capacite int, hostname string) *LogBuffer {
	if capacite < 1 {
		capacite = 1
	}
	// Mille cases d'avance, pas la capacité entière : voir « La forme ».
	avance := 1000
	if avance > capacite {
		avance = capacite
	}
	return &LogBuffer{
		entries:  make([]LogEntry, 0, avance),
		maxSize:  capacite,
		hostname: hostname,
	}
}

// getBuffer rend le tampon du processus.
func getBuffer() *LogBuffer {
	bufferOnce.Do(func() {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "localhost"
		}
		globalBuffer = nouveauTampon(CapaciteDuTampon, hostname)
	})
	return globalBuffer
}

// addEntry ajoute une ligne. Tampon plein, elle remplace la plus ancienne —
// sans allocation ni recopie.
func (b *LogBuffer) addEntry(entry LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.entries) < b.maxSize {
		b.entries = append(b.entries, entry)
		return
	}
	b.entries[b.plusAncienne] = entry
	b.plusAncienne++
	if b.plusAncienne == b.maxSize {
		b.plusAncienne = 0
	}
}

// recentes rend une copie des lignes, la plus récente en premier.
//
// Une COPIE : l'appelant filtre et pagine hors du verrou. Garder le verrou
// pendant ce travail bloquerait toutes les écritures de journal du core le
// temps d'une consultation.
func (b *LogBuffer) recentes() []LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	n := len(b.entries)
	out := make([]LogEntry, n)
	if n == 0 {
		return out
	}
	// La plus récente précède la plus ancienne dans l'anneau. Tant que le
	// tampon n'est pas plein, plusAncienne vaut zéro et la plus récente est
	// donc la dernière case : la même formule sert les deux cas.
	i := b.plusAncienne
	for k := 0; k < n; k++ {
		i--
		if i < 0 {
			i = n - 1
		}
		out[k] = b.entries[i]
	}
	return out
}
