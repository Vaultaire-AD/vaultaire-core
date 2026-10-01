package tramesmanager

import (
	"bytes"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/sendmessage"
)

// Tests du cadrage des trames Ducky côté SDK (TO-DO 101). Jumeaux de ceux du
// core : la première fois, le garde-fou n'avait été posé que d'un côté.

func paireAvecDelai(t *testing.T) (client, serveur net.Conn) {
	t.Helper()
	client, serveur = net.Pipe()
	t.Cleanup(func() { client.Close(); serveur.Close() })
	_ = serveur.SetReadDeadline(time.Now().Add(5 * time.Second))
	return client, serveur
}

func TestUnChampTailleDUnOctetEstRefuseSansPanique(t *testing.T) {
	client, serveur := paireAvecDelai(t)
	go func() { _, _ = client.Write([]byte{0x01, 0xff}) }()

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur « \\x01\\xff » : %v\n%s", r, debug.Stack())
		}
	}()
	_, err := Read_Header_Size(serveur)
	var cadrage *ErreurCadrage
	if !errors.As(err, &cadrage) {
		t.Fatalf("premier octet à 1 : erreur de cadrage attendue, obtenu %v", err)
	}
	if _, err := Read_Message_Size(serveur, 1); err == nil {
		t.Fatal("Read_Message_Size accepte un champ taille d'un octet")
	}
}

// 0 en particulier : la boucle de réception le sautait comme « rien à lire ».
// Aucun émetteur ne l'envoie ; l'accepter, c'est lire l'octet suivant comme un
// nouvel en-tête au milieu d'un flux déjà perdu.
func TestSeulLeChampTailleDeDeuxOctetsEstAccepte(t *testing.T) {
	for v := 0; v < 256; v++ {
		client, serveur := paireAvecDelai(t)
		octet := byte(v)
		go func() { _, _ = client.Write([]byte{octet}) }()
		got, err := Read_Header_Size(serveur)
		switch {
		case v == TailleChampTaille && (err != nil || got != TailleChampTaille):
			t.Fatalf("premier octet %d refusé (%v) : c'est la seule valeur légale", v, err)
		case v != TailleChampTaille && err == nil:
			t.Fatalf("premier octet %d accepté : seul %d est légal", v, TailleChampTaille)
		}
	}
}

// Une trame livrée octet par octet — légal pour TCP, courant sur une liaison
// lente — doit arriver intacte, et la suivante à sa place.
func TestUneTrameLivreeOctetParOctetArriveIntacte(t *testing.T) {
	client, serveur := paireAvecDelai(t)

	premier := bytes.Repeat([]byte("B"), 700)
	second := []byte("02_11\nserveur_central\ncle\n")
	t1, err := sendmessage.CadrerTrame(premier)
	if err != nil {
		t.Fatal(err)
	}
	t2, err := sendmessage.CadrerTrame(second)
	if err != nil {
		t.Fatal(err)
	}
	flux := append(t1, t2...)
	go func() {
		for i := range flux {
			if _, err := client.Write(flux[i : i+1]); err != nil {
				return
			}
		}
	}()

	for i, attendu := range [][]byte{premier, second} {
		h, err := Read_Header_Size(serveur)
		if err != nil {
			t.Fatalf("trame %d : en-tête : %v — le flux est désynchronisé", i+1, err)
		}
		taille, err := Read_Message_Size(serveur, h)
		if err != nil {
			t.Fatalf("trame %d : taille : %v", i+1, err)
		}
		if taille != len(attendu) {
			t.Fatalf("trame %d : taille lue %d, envoyée %d — lecture courte du champ taille", i+1, taille, len(attendu))
		}
		corps, err := LireCorps(serveur, taille)
		if err != nil {
			t.Fatalf("trame %d : corps : %v", i+1, err)
		}
		if !bytes.Equal(corps, attendu) {
			t.Fatalf("trame %d : corps différent de l'envoi — lecture courte du corps", i+1)
		}
	}
}

func TestUnCorpsAnnonceVideEstRefuse(t *testing.T) {
	client, serveur := paireAvecDelai(t)
	go func() { _, _ = client.Write([]byte{0x00, 0x00}) }()
	if _, err := Read_Message_Size(serveur, TailleChampTaille); err == nil {
		t.Fatal("un corps annoncé vide est accepté")
	}
}

func TestLaBorneDEmissionEgaleLaBorneDeLecture(t *testing.T) {
	if sendmessage.TailleMaxCorps != TailleMaxCorps {
		t.Fatalf("sendmessage.TailleMaxCorps = %d, tramesmanager.TailleMaxCorps = %d", sendmessage.TailleMaxCorps, TailleMaxCorps)
	}
	if _, err := sendmessage.CompileMessageSize(make([]byte, TailleMaxCorps)); err != nil {
		t.Fatalf("la plus grande trame légale est refusée : %v", err)
	}
	if _, err := sendmessage.CompileMessageSize(make([]byte, TailleMaxCorps+1)); err == nil {
		t.Fatal("une trame de 65536 octets est acceptée : annoncée modulo 65536, elle désynchroniserait le tunnel")
	}
}

// Le garde-fou que le core avait et que le SDK n'avait pas : une trame de
// moins de trois lignes indexait lines[1] et lines[2] hors bornes, chez
// l'agent, le proxy, Nexus et le client Windows.
func TestUneTrameTropCourteNePaniquePas(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("PANIQUE sur une trame courte : %v\n%s", r, debug.Stack())
		}
	}()
	for _, trame := range []string{"", "01_02", "01_02\nserveur_central"} {
		if got := ParseTrames(trame); len(got.Message_Order) != 0 {
			t.Errorf("ParseTrames(%q) rend le code %v : une trame incomplète doit rendre une structure vide", trame, got.Message_Order)
		}
	}
	if got := ParseTrames("01_02\nserveur_central\ncle"); strings.Join(got.Message_Order, "_") != "01_02" {
		t.Errorf("une trame de trois lignes, la plus courte légale, est rejetée : %+v", got)
	}
}

// Sentinelle : aucune lecture directe du socket dans le SDK. Une seule
// réintroduite rouvre la lecture courte, et rien d'autre ne le signalerait.
func TestAucuneLectureDirecteDuSocketDansLeSDK(t *testing.T) {
	lectureDirecte := regexp.MustCompile(`(?i)conn\.Read\(`)
	racine := filepath.Join("..", "..")
	err := filepath.WalkDir(racine, func(chemin string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(chemin, ".go") || strings.HasSuffix(chemin, "_test.go") {
			return nil
		}
		contenu, err := os.ReadFile(chemin)
		if err != nil {
			return err
		}
		if lectureDirecte.Match(contenu) {
			t.Errorf("%s lit le socket avec conn.Read : employer io.ReadFull ou LireCorps — voir trames_manager/cadrage.go", chemin)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
