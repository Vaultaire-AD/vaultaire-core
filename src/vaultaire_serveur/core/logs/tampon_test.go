package logs

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func textes(entrees []LogEntry) []string {
	out := make([]string, len(entrees))
	for i, e := range entrees {
		out[i] = e.Message
	}
	return out
}

func remplir(t *LogBuffer, de, a int) {
	for i := de; i <= a; i++ {
		t.addEntry(LogEntry{Message: fmt.Sprint(i)})
	}
}

func attendre(t *testing.T, tampon *LogBuffer, voulu ...string) {
	t.Helper()
	obtenu := textes(tampon.recentes())
	if fmt.Sprint(obtenu) != fmt.Sprint(voulu) {
		t.Fatalf("lignes rendues %v, attendu %v", obtenu, voulu)
	}
}

// Avant le plein, puis juste plein, puis à chaque ligne au-delà : la plus
// récente est en tête, et seule la plus ancienne disparaît.
func TestLeTamponRendLesPlusRecentesDAbord(t *testing.T) {
	tampon := nouveauTampon(4, "h")
	attendre(t, tampon)

	remplir(tampon, 1, 1)
	attendre(t, tampon, "1")

	remplir(tampon, 2, 3)
	attendre(t, tampon, "3", "2", "1")

	remplir(tampon, 4, 4) // plein, à ras
	attendre(t, tampon, "4", "3", "2", "1")

	remplir(tampon, 5, 5) // la première ligne en trop écrase la plus ancienne
	attendre(t, tampon, "5", "4", "3", "2")

	remplir(tampon, 6, 8) // un tour complet
	attendre(t, tampon, "8", "7", "6", "5")

	remplir(tampon, 9, 9) // et l'indice repart de zéro
	attendre(t, tampon, "9", "8", "7", "6")
}

// Plusieurs tours : l'ordre tient quel que soit l'endroit où l'on s'arrête.
func TestLeTamponTientSurPlusieursTours(t *testing.T) {
	const capacite = 7
	for total := 0; total <= 4*capacite; total++ {
		tampon := nouveauTampon(capacite, "h")
		remplir(tampon, 1, total)
		obtenu := tampon.recentes()

		voulu := total
		if voulu > capacite {
			voulu = capacite
		}
		if len(obtenu) != voulu {
			t.Fatalf("%d lignes écrites : %d rendues, attendu %d", total, len(obtenu), voulu)
		}
		for k, e := range obtenu {
			if attendu := fmt.Sprint(total - k); e.Message != attendu {
				t.Fatalf("%d lignes écrites : rang %d = %s, attendu %s (%v)",
					total, k, e.Message, attendu, textes(obtenu))
			}
		}
	}
}

// Ce que rend `recentes` est une copie : la modifier ne touche pas au tampon,
// et une ligne écrite ensuite ne la change pas.
func TestLeTamponRendUneCopie(t *testing.T) {
	tampon := nouveauTampon(3, "h")
	remplir(tampon, 1, 3)
	rendu := tampon.recentes()
	rendu[0].Message = "falsifié"
	remplir(tampon, 4, 4)
	if rendu[1].Message != "2" {
		t.Errorf("la copie a bougé après une écriture : %v", textes(rendu))
	}
	attendre(t, tampon, "4", "3", "2")
}

// TO-DO 154 — le défaut lui-même. Tampon plein, une ligne de plus ne doit
// RIEN allouer : elle allouait la capacité entière et y recopiait tout.
func TestUneLigneDePlusNAlloueRien(t *testing.T) {
	tampon := nouveauTampon(CapaciteDuTampon, "h")
	remplir(tampon, 1, CapaciteDuTampon)
	ligne := LogEntry{Message: "x", Level: "INFO"}

	if n := testing.AllocsPerRun(1000, func() { tampon.addEntry(ligne) }); n != 0 {
		t.Fatalf("une ligne ajoutée à un tampon plein alloue %.0f fois — elle ne doit rien allouer", n)
	}
	if got := len(tampon.entries); got != CapaciteDuTampon {
		t.Errorf("le tampon porte %d entrées, attendu %d", got, CapaciteDuTampon)
	}
	if cap(tampon.entries) > 2*CapaciteDuTampon {
		t.Errorf("la tranche a grossi jusqu'à %d cases", cap(tampon.entries))
	}
}

// Le garde-fou de durée, large exprès : vingt mille lignes au-delà du plein
// prenaient plus d'une minute. Ce test ne mesure pas une performance, il
// refuse le retour d'une recopie par ligne.
func TestVingtMilleLignesAuDelaDuPlein(t *testing.T) {
	tampon := nouveauTampon(CapaciteDuTampon, "h")
	remplir(tampon, 1, CapaciteDuTampon)

	debut := time.Now()
	ligne := LogEntry{Message: "x"}
	for i := 0; i < 20000; i++ {
		tampon.addEntry(ligne)
	}
	if d := time.Since(debut); d > 2*time.Second {
		t.Fatalf("20 000 lignes au-delà du plein ont pris %s : le tampon recopie de nouveau à chaque ligne", d)
	}
}

// Un core qui écrit peu ne garde pas la capacité entière en mémoire.
func TestLeTamponNeReservePasToutDEmblee(t *testing.T) {
	tampon := nouveauTampon(CapaciteDuTampon, "h")
	remplir(tampon, 1, 10)
	if c := cap(tampon.entries); c >= CapaciteDuTampon {
		t.Errorf("dix lignes écrites, %d cases réservées", c)
	}
}

func TestCapaciteMinimale(t *testing.T) {
	tampon := nouveauTampon(0, "h")
	remplir(tampon, 1, 3)
	attendre(t, tampon, "3")
}

// Écritures et lectures mêlées : à lancer sous -race.
func TestLeTamponSousConcurrence(t *testing.T) {
	tampon := nouveauTampon(50, "h")
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				tampon.addEntry(LogEntry{Message: "x"})
				if i%25 == 0 {
					if n := len(tampon.recentes()); n > 50 {
						t.Errorf("%d lignes rendues pour une capacité de 50", n)
					}
				}
			}
		}()
	}
	wg.Wait()
	if n := len(tampon.recentes()); n != 50 {
		t.Errorf("%d lignes gardées, attendu 50", n)
	}
}

func BenchmarkTamponPlein(b *testing.B) {
	tampon := nouveauTampon(CapaciteDuTampon, "h")
	for i := 0; i < CapaciteDuTampon; i++ {
		tampon.addEntry(LogEntry{Message: "x"})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tampon.addEntry(LogEntry{Message: "x"})
	}
}
