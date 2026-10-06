package tramesmanager

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"vaultaire/ducky-network/sendmessage"
)

// Tests du cadrage des trames Ducky (TO-DO 101). Voir cadrage.go.

// ecrireOctetParOctet envoie data un octet à la fois : c'est le pire découpage
// que TCP puisse produire, et il est légal. net.Pipe ne fusionne pas les
// écritures, donc chaque Read côté lecteur ne rend qu'un octet.
func ecrireOctetParOctet(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	go func() {
		for i := range data {
			if _, err := conn.Write(data[i : i+1]); err != nil {
				return
			}
		}
	}()
}

func paireAvecDelai(t *testing.T) (client, serveur net.Conn) {
	t.Helper()
	client, serveur = net.Pipe()
	t.Cleanup(func() { client.Close(); serveur.Close() })
	_ = serveur.SetReadDeadline(time.Now().Add(5 * time.Second))
	return client, serveur
}

// Deux octets anonymes, « \x01\xff », faisaient paniquer le core : le premier
// dimensionnait le tampon de la taille, binary.BigEndian.Uint16 lisait hors de
// ses bornes. Le recover sauvait le processus, mais chaque panique écrivait sa
// pile en CRITICAL — de quoi noyer le journal commun à quelques octets par
// seconde.
func TestUnChampTailleDUnOctetNePaniquePlus(t *testing.T) {
	client, serveur := paireAvecDelai(t)
	go func() { _, _ = client.Write([]byte{0x01, 0xff}) }()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur « \\x01\\xff » : un inconnu peut encore remplir le journal de piles.\n%v\n%s", r, debug.Stack())
		}
	}()
	if got := Read_Header_Size(serveur); got != 0 {
		t.Fatalf("Read_Header_Size = %d sur un premier octet à 1 : la connexion devait être fermée (0)", got)
	}
	if _, err := Read_Message_Size(serveur, 1); err == nil {
		t.Fatal("Read_Message_Size accepte un champ taille d'un octet : c'est le chemin de la panique")
	}
}

// Le premier octet n'a qu'une valeur légale. Toutes les autres ferment la
// connexion — y compris 0, qui ne veut rien dire, et les grandes valeurs, qui
// feraient allouer avant de lire.
func TestSeulLeChampTailleDeDeuxOctetsEstAccepte(t *testing.T) {
	for v := 0; v < 256; v++ {
		client, serveur := paireAvecDelai(t)
		octet := byte(v)
		go func() { _, _ = client.Write([]byte{octet}) }()
		got := Read_Header_Size(serveur)
		switch {
		case v == TailleChampTaille && got != TailleChampTaille:
			t.Fatalf("premier octet %d refusé : c'est la seule valeur légale, plus aucune trame ne passerait", v)
		case v != TailleChampTaille && got != 0:
			t.Fatalf("premier octet %d accepté (rendu %d) : seul %d est légal", v, got, TailleChampTaille)
		}
	}
}

// TCP peut rendre une trame octet par octet, sans attaquant, sur une liaison
// lente. conn.Read prenait alors un octet pour la taille entière, puis un
// corps tronqué, et la fin passait pour l'en-tête suivant : échec
// d'authentification intermittent. Deux trames de suite doivent arriver
// intactes, et la seconde à sa place.
func TestUneTrameLivreeOctetParOctetArriveIntacte(t *testing.T) {
	client, serveur := paireAvecDelai(t)

	premier := bytes.Repeat([]byte("A"), 300) // taille > 255 : les deux octets comptent
	second := []byte("02_11\nserveur_central\ncle\n")
	t1, err := sendmessage.CadrerTrame(premier)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := sendmessage.CadrerTrame(second)
	if err != nil {
		t.Fatal(err)
	}
	ecrireOctetParOctet(t, client, append(t1, t2...))

	for i, attendu := range [][]byte{premier, second} {
		h := Read_Header_Size(serveur)
		if h != TailleChampTaille {
			t.Fatalf("trame %d : en-tête lu %d, attendu %d — le flux est désynchronisé", i+1, h, TailleChampTaille)
		}
		taille, err := Read_Message_Size(serveur, h)
		if err != nil {
			t.Fatalf("trame %d : taille illisible : %v", i+1, err)
		}
		if taille != len(attendu) {
			t.Fatalf("trame %d : taille lue %d, envoyée %d — lecture courte du champ taille", i+1, taille, len(attendu))
		}
		corps, err := lireCorps(serveur, taille)
		if err != nil {
			t.Fatalf("trame %d : corps illisible : %v", i+1, err)
		}
		if !bytes.Equal(corps, attendu) {
			t.Fatalf("trame %d : corps reçu différent du corps envoyé — lecture courte du corps", i+1)
		}
	}
}

// Aucun émetteur n'envoie un corps vide. Un zéro vient d'un flux désynchronisé
// ou forgé : on ferme plutôt que de le traiter comme une trame.
func TestUnCorpsAnnonceVideFermeLaConnexion(t *testing.T) {
	client, serveur := paireAvecDelai(t)
	go func() { _, _ = client.Write([]byte{0x00, 0x00}) }()
	if _, err := Read_Message_Size(serveur, TailleChampTaille); err == nil {
		t.Fatal("un corps annoncé vide est accepté")
	}
}

// Le core et l'émetteur partagent la même borne. Si l'une bougeait seule, le
// core émettrait des trames qu'il refuserait de lire, ou l'inverse.
func TestLaBorneDEmissionEgaleLaBorneDeLecture(t *testing.T) {
	if sendmessage.TailleMaxCorps != TailleMaxCorps {
		t.Fatalf("sendmessage.TailleMaxCorps = %d, tramesmanager.TailleMaxCorps = %d : elles doivent être égales",
			sendmessage.TailleMaxCorps, TailleMaxCorps)
	}
	if _, err := sendmessage.CompileMessageSize(make([]byte, TailleMaxCorps)); err != nil {
		t.Fatalf("une trame de %d octets, la plus grande légale, est refusée : %v", TailleMaxCorps, err)
	}
	if _, err := sendmessage.CompileMessageSize(make([]byte, TailleMaxCorps+1)); err == nil {
		t.Fatalf("une trame de %d octets est acceptée : elle partirait annoncée modulo 65536 et désynchroniserait le tunnel",
			TailleMaxCorps+1)
	}
}

// Sentinelle : cadrage.go est le seul endroit du paquet qui lit le socket.
// Un conn.Read réintroduit ailleurs rouvre la lecture courte, et rien d'autre
// ne le signalerait.
func TestAucuneLectureDirecteDuSocketHorsDuCadrage(t *testing.T) {
	lectureDirecte := regexp.MustCompile(`(?i)conn\.Read\(`)
	fichiers, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fichiers {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		contenu, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if lectureDirecte.Match(contenu) {
			t.Errorf("%s lit le socket avec conn.Read : employer io.ReadFull (lireCorps, lireTailleCorps) — voir cadrage.go", f)
		}
	}
}
