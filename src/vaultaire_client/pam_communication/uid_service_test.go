package pamcommunication

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	localusermanagement "vaultaire_client/tools/local_user_management"
)

// Tests du service d'allocation d'identifiants.
//
// # La régression qu'ils empêchent de revenir
//
// Le module NSS a cessé de répondre pour un utilisateur absent de la carte. Or
// sshd appelle getpwnam AVANT toute authentification et refuse un compte
// inconnu sans même exécuter AuthorizedKeysCommand.
//
// Résultat : « Permission denied (publickey) », et AUCUN journal — puisque rien
// du côté Vaultaire n'était exécuté. La carte, elle, ne se remplissait qu'au
// provisionnement, lequel suit l'authentification. La chaîne se refermait sur
// elle-même et aucune première connexion n'était possible.
//
// Les tests précédents couvraient la carte et le module NSS séparément, chacun
// correctement. Aucun ne posait la seule question qui comptait : « un
// utilisateur jamais vu peut-il obtenir une identité ? »

func serviceUIDDeTest(t *testing.T) string {
	t.Helper()

	// Chemin court : sun_path est limité à 108 octets, et t.TempDir() dépasse.
	base, err := os.MkdirTemp("/tmp", "vltuid")
	if err != nil {
		t.Fatalf("répertoire temporaire : %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })

	// La carte vit dans le même temporaire : on ne touche pas à /etc.
	t.Setenv("VAULTAIRE_UID_MAP_DIR", base)

	chemin := filepath.Join(base, "p", "uid.sock")
	go serveUIDSocket(chemin)

	for i := 0; i < 200; i++ {
		if _, err := os.Stat(chemin); err == nil {
			return chemin
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("le socket %s n'a pas été créé", chemin)
	return ""
}

// demander joue le rôle du module NSS.
func demander(t *testing.T, chemin, nom string) string {
	t.Helper()

	conn, err := net.Dial("unix", chemin)
	if err != nil {
		t.Fatalf("connexion au service : %v", err)
	}
	defer func() { _ = conn.Close() }()

	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline : %v", err)
	}
	if _, err := conn.Write([]byte(nom + "\n")); err != nil {
		t.Fatalf("écriture : %v", err)
	}

	ligne, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && ligne == "" {
		t.Fatalf("lecture : %v", err)
	}
	return strings.TrimSpace(ligne)
}

// TestPremiereConnexionObtientUneIdentite est LE test qui manquait.
//
// Un utilisateur que la machine n'a jamais vu doit obtenir un identifiant, sans
// quoi sshd le refuse avant même que Vaultaire n'entre en jeu.
func TestPremiereConnexionObtientUneIdentite(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	reponse := demander(t, chemin, "jamais-vu@vaultaire.fr")
	if reponse == "" {
		t.Fatal("aucune identité pour un utilisateur inconnu : " +
			"sshd refuserait la connexion sans exécuter AuthorizedKeysCommand, " +
			"et aucune première connexion ne serait possible")
	}

	parts := strings.Split(reponse, ":")
	if len(parts) != 3 || parts[0] != "jamais-vu@vaultaire.fr" {
		t.Fatalf("réponse %q mal formée", reponse)
	}

	// Et l'identité doit être PERSISTÉE : la résolution suivante passera par la
	// carte, sans repasser par le service.
	entries, err := localusermanagement.LoadUIDMap()
	if err != nil {
		t.Fatalf("lecture de la carte : %v", err)
	}
	if _, present := entries["jamais-vu@vaultaire.fr"]; !present {
		t.Error("l'identité attribuée n'a pas été écrite dans la carte")
	}
}

// TestIdentiteStableEntreDeuxDemandes : deux résolutions du même nom donnent le
// même numéro.
//
// Un UID qui changerait entre deux connexions laisserait des fichiers
// appartenant à un numéro que plus personne ne porte.
func TestIdentiteStableEntreDeuxDemandes(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	premier := demander(t, chemin, "alice@vaultaire.fr")
	_ = demander(t, chemin, "bob@vaultaire.fr") // un autre passe entre les deux
	second := demander(t, chemin, "alice@vaultaire.fr")

	if premier != second {
		t.Errorf("l'identité d'alice a changé : %q puis %q", premier, second)
	}
}

// TestDeuxUtilisateursDeuxIdentites : la séparation reste garantie.
//
// C'est la propriété pour laquelle tout ce mécanisme existe. La rétablir par ce
// chemin ne doit pas la reperdre.
func TestDeuxUtilisateursDeuxIdentites(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	a := demander(t, chemin, "alice@vaultaire.fr")
	b := demander(t, chemin, "bob@vaultaire.fr")

	if a == b {
		t.Fatalf("alice et bob reçoivent la même identité (%q) : aucune séparation", a)
	}
	if strings.Split(a, ":")[1] == strings.Split(b, ":")[1] {
		t.Error("UID identiques")
	}
}

// TestNomsRefuses : la liste blanche.
//
// Le nom vient d'un appelant quelconque et finit écrit dans un fichier que la
// libc analyse. Un deux-points ou un saut de ligne fabriquerait une seconde
// entrée à partir d'une seule — et cette entrée pourrait porter l'UID 0.
func TestNomsRefuses(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	refuses := []struct{ nom, pourquoi string }{
		{"root", "pas de domaine : c'est un compte local, /etc/passwd fait autorité"},
		{"", "vide"},
		{"@vaultaire.fr", "nom vide avant l'arobase"},
		{"alice@", "domaine vide"},
		{"a@b@c", "deux arobases : la forme serait choisie par l'appelant"},
		{"alice:0:0", "deux-points : fabriquerait une entrée root dans la carte"},
		{"alice@dom evil", "espace"},
		{"alice@dom/../x", "barre oblique"},
		{"alice@dom$(id)", "métacaractère de shell"},
		{strings.Repeat("a", 200) + "@dom", "nom aberrant"},
	}

	for _, c := range refuses {
		reponse := demander(t, chemin, c.nom)
		if reponse != "" {
			t.Errorf("le nom %q a été accepté (%s) → %q", c.nom, c.pourquoi, reponse)
		}
	}

	// Et rien de tout cela ne doit avoir atterri dans la carte.
	entries, err := localusermanagement.LoadUIDMap()
	if err != nil {
		t.Fatalf("lecture de la carte : %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("la carte contient %d entrée(s) après des noms refusés : %v", len(entries), entries)
	}
}

// TestJamaisDUIDPrivilegie : quelle que soit la demande, jamais 0.
func TestJamaisDUIDPrivilegie(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	for _, nom := range []string{"root@vaultaire.fr", "admin@vaultaire.fr", "daemon@vaultaire.fr"} {
		reponse := demander(t, chemin, nom)
		if reponse == "" {
			continue
		}
		parts := strings.Split(reponse, ":")
		if len(parts) != 3 {
			t.Fatalf("réponse %q mal formée", reponse)
		}
		if parts[1] == "0" || parts[2] == "0" {
			t.Fatalf("le service a rendu l'UID 0 pour %q", nom)
		}
	}
}

// TestSocketLisibleParTous : le service doit être joignable sans privilège.
//
// NSS est chargé dans TOUS les processus de la machine : « ls -l » lancé par un
// utilisateur ordinaire résout des UID. Un socket en 0600 rendrait la
// résolution impossible pour tout le monde sauf root — donc des noms affichés
// en numéros, et surtout un sshd qui ne résout plus rien après avoir changé
// d'identité.
//
// C'est l'exact inverse du canal PAM, qui lui transporte des mots de passe et
// doit rester fermé. Les deux sockets sont séparés pour cette raison.
func TestSocketLisibleParTous(t *testing.T) {
	chemin := serviceUIDDeTest(t)

	info, err := os.Stat(chemin)
	if err != nil {
		t.Fatalf("stat : %v", err)
	}
	if info.Mode().Perm()&0o006 == 0 {
		t.Errorf("mode %o : le socket n'est pas joignable par les autres, "+
			"la résolution de noms échouerait pour tout processus non privilégié",
			info.Mode().Perm())
	}

	// Le répertoire doit être traversable, sinon le mode du socket ne sert à rien.
	dir, err := os.Stat(filepath.Dir(chemin))
	if err != nil {
		t.Fatalf("stat du répertoire : %v", err)
	}
	if dir.Mode().Perm()&0o001 == 0 {
		t.Errorf("répertoire en %o : non traversable, le socket est inatteignable",
			dir.Mode().Perm())
	}
}

// TestPlafondDAllocation : un appelant hostile ne peut pas épuiser la plage.
//
// Le service est ouvert à tous par nécessité. Sans plafond, un script local
// remplirait la carte et un utilisateur légitime ne pourrait plus obtenir
// d'identité — un déni de service à quelques lignes de shell.
func TestPlafondDAllocation(t *testing.T) {
	base, err := os.MkdirTemp("/tmp", "vltcap")
	if err != nil {
		t.Fatalf("répertoire temporaire : %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	t.Setenv("VAULTAIRE_UID_MAP_DIR", base)

	// Une carte déjà au plafond.
	var b strings.Builder
	for i := 0; i < maxAllocationsALaVolee; i++ {
		b.WriteString(strings.Repeat("u", 4) + string(rune('a'+i%26)) +
			itoa(i) + "@dom:" + itoa(localusermanagement.UIDMin+i) + ":" +
			itoa(localusermanagement.UIDMin+i) + "\n")
	}
	if err := os.WriteFile(filepath.Join(base, "uid.map"), []byte(b.String()), 0o644); err != nil {
		t.Fatalf("écriture de la carte : %v", err)
	}

	chemin := filepath.Join(base, "p", "uid.sock")
	go serveUIDSocket(chemin)
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(chemin); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if reponse := demander(t, chemin, "detrop@vaultaire.fr"); reponse != "" {
		t.Errorf("allocation accordée au-delà du plafond : %q", reponse)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var chiffres []byte
	for n > 0 {
		chiffres = append([]byte{byte('0' + n%10)}, chiffres...)
		n /= 10
	}
	return string(chiffres)
}
