package pamcommunication

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vaultaire_client/logs"
	localusermanagement "vaultaire_client/tools/local_user_management"
)

// Service d'allocation d'identifiants pour le module NSS.
//
// # Le problème qu'il résout
//
// sshd appelle `getpwnam` AVANT toute authentification, et refuse un compte
// inconnu sans même exécuter `AuthorizedKeysCommand`. Le module NSS doit donc
// pouvoir répondre pour un utilisateur qu'il n'a jamais vu.
//
// Or la carte `/etc/vaultaire/uid.map` n'était remplie que par le
// provisionnement, lui-même déclenché par une authentification réussie. La
// chaîne se refermait sur elle-même : aucune première connexion n'était
// possible, et le symptôme était un « Permission denied (publickey) » sans la
// moindre trace dans les journaux — puisque rien du côté Vaultaire n'était
// exécuté.
//
// # Pourquoi un socket SÉPARÉ du canal PAM
//
// Ce sont deux choses de nature opposée, et les confondre serait une faute.
//
//	/run/vaultaire/pam.sock   0600 root   mots de passe, réponses d'autorisation
//	/run/vaultaire/uid.sock   0666 root   un nom, un numéro
//
// Le canal PAM est réservé à root parce qu'il transporte des secrets et décide
// de l'accès. Celui-ci ne transporte rien de secret et ne décide de rien : il
// attribue un numéro, exactement comme `/etc/passwd` en publie. Il DOIT être
// ouvert à tous, parce que NSS est chargé dans n'importe quel processus —
// `ls -l` lancé par un utilisateur ordinaire résout des UID.
//
// Les faire partager un socket obligerait à ouvrir le canal des mots de passe à
// tout le monde. C'est précisément la faille qui vient d'être corrigée.
//
// # Ce qu'un appelant hostile peut en tirer
//
// Il peut créer des entrées dans la carte en demandant des noms inventés, et
// donc consommer la plage d'UID. C'est une nuisance, pas une élévation :
//
//   - aucun UID hors de la plage 5000-60000 n'est jamais rendu ;
//   - une entrée dans la carte ne donne AUCUN droit — ni compte local, ni mot
//     de passe, ni clé. L'authentification reste entièrement du ressort du core ;
//   - le nom doit ressembler à un utilisateur du domaine, ce qui limite déjà
//     l'espace ;
//   - un plafond borne le nombre d'entrées créées à la volée.
//
// Le pire résultat est un fichier encombré, réparable en le supprimant.
const (
	// UIDSocketName vit dans le même répertoire que le canal PAM, mais celui-ci
	// est en 0700 root — donc inaccessible aux processus ordinaires. Le socket
	// d'allocation a besoin d'être joignable par tous : il lui faut son propre
	// répertoire.
	UIDSocketDir  = "/run/vaultaire/public"
	UIDSocketName = "uid.sock"
)

// UIDSocketPath est une variable pour que les tests la déplacent.
var UIDSocketPath = filepath.Join(UIDSocketDir, UIDSocketName)

// maxAllocationsALaVolee borne ce qu'un appelant non authentifié peut créer.
//
// Sans plafond, un script local remplirait la plage entière en quelques
// secondes, et un utilisateur légitime ne pourrait plus obtenir d'identité.
// 2000 laisse largement de quoi fonctionner sur un poste, tout en gardant la
// nuisance visible et bornée.
const maxAllocationsALaVolee = 2000

// UIDAllocationServer répond aux demandes d'identifiant du module NSS.
//
// Protocole volontairement minimal, une ligne dans chaque sens :
//
//	→  nom@domaine\n
//	←  nom@domaine:uid:gid\n      si le nom est acceptable
//	←  \n                          sinon (ligne vide = inconnu)
//
// Une ligne de texte plutôt que du JSON : l'analyseur est du C chargé dans tous
// les processus de la machine. Moins il a de travail à faire sur une entrée
// qu'il n'a pas produite, mieux c'est.
func UIDAllocationServer() {
	serveUIDSocket(UIDSocketPath)
}

func serveUIDSocket(chemin string) {
	dir := filepath.Dir(chemin)

	// 0755 et non 0700 : le répertoire doit être TRAVERSABLE par tous, sinon le
	// socket qu'il contient est inatteignable quel que soit son propre mode.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket UID : création de %s : %v", dir, err))
		return
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket UID : mode de %s : %v", dir, err))
		return
	}

	if err := os.RemoveAll(chemin); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket UID : nettoyage : %v", err))
	}

	// umask 0 pendant le bind : le socket doit naître en 0666. Le poser après
	// coup laisserait une fenêtre pendant laquelle NSS échouerait pour les
	// processus non privilégiés — donc des connexions refusées au démarrage.
	ancienMasque := syscall.Umask(0)
	ln, err := net.Listen("unix", chemin)
	syscall.Umask(ancienMasque)
	if err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket UID : écoute impossible : %v", err))
		return
	}
	defer func() { _ = ln.Close() }()

	if err := os.Chmod(chemin, 0o666); err != nil {
		logs.Write_log("CRITICAL", fmt.Sprintf("socket UID : mode : %v", err))
		return
	}

	logs.Write_log("INFO", "socket UID : allocation d'identifiants disponible sur "+chemin)

	for {
		conn, err := ln.Accept()
		if err != nil {
			logs.Write_log("ERROR", fmt.Sprintf("socket UID : accept : %v", err))
			continue
		}
		logs.Go("allocation UID", func() { handleUIDRequest(conn) })
	}
}

func handleUIDRequest(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Délai serré des deux côtés : ce service est sur le chemin de CHAQUE
	// résolution de nom de la machine. Un appelant qui ouvrirait la connexion
	// sans rien envoyer immobiliserait une goroutine ; mille appelants
	// immobiliseraient l'agent.
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return
	}

	lecteur := bufio.NewReader(conn)
	ligne, err := lecteur.ReadString('\n')
	if err != nil && ligne == "" {
		return
	}

	nom := strings.TrimSpace(ligne)
	if !nomDomaineAcceptable(nom) {
		_, _ = conn.Write([]byte("\n"))
		return
	}

	entries, err := localusermanagement.LoadUIDMap()
	if err == nil {
		if e, connu := entries[nom]; connu {
			// Déjà dans la carte : on répond sans rien écrire. C'est le cas
			// courant une fois le parc en régime, et il ne doit rien coûter.
			repondre(conn, e)
			return
		}
		if len(entries) >= maxAllocationsALaVolee {
			logs.Write_log("CRITICAL", fmt.Sprintf(
				"socket UID : plafond de %d entrées atteint, allocation refusée pour %q — "+
					"quelqu'un remplit la carte, vérifiez /etc/vaultaire/uid.map",
				maxAllocationsALaVolee, nom))
			_, _ = conn.Write([]byte("\n"))
			return
		}
	}

	entry, err := localusermanagement.EnsureUIDMapping(nom)
	if err != nil {
		logs.Write_log("ERROR", fmt.Sprintf("socket UID : allocation impossible pour %q : %v", nom, err))
		_, _ = conn.Write([]byte("\n"))
		return
	}

	repondre(conn, entry)
}

func repondre(conn net.Conn, e localusermanagement.UIDEntry) {
	_, _ = conn.Write([]byte(fmt.Sprintf("%s:%d:%d\n", e.Username, e.UID, e.GID)))
}

// nomDomaineAcceptable filtre ce qui peut entrer dans la carte.
//
// Liste BLANCHE, et non liste noire. Le nom vient d'un appelant quelconque et
// finira écrit dans un fichier que la libc analyse : il ne doit contenir ni
// deux-points — le séparateur de la carte — ni saut de ligne, ni rien qui
// puisse fabriquer une seconde entrée à partir d'une seule.
//
// Le « @ » est exigé : ce service ne sert qu'aux comptes du domaine. Les comptes
// locaux sont l'affaire de /etc/passwd, et leur en fabriquer un ici masquerait
// le vrai.
func nomDomaineAcceptable(nom string) bool {
	if nom == "" || len(nom) > 128 {
		return false
	}
	if !strings.Contains(nom, "@") {
		return false
	}
	// Un seul « @ » : « a@b@c » n'est pas un nom d'utilisateur du domaine, et
	// l'accepter reviendrait à laisser l'appelant choisir la forme.
	if strings.Count(nom, "@") != 1 {
		return false
	}
	for _, r := range nom {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-', r == '@':
		default:
			return false
		}
	}
	// Ni le nom ni le domaine ne peuvent être vides.
	parts := strings.SplitN(nom, "@", 2)
	return parts[0] != "" && parts[1] != ""
}

// StartUIDAllocationServer lance le service dans sa propre goroutine.
//
// Séparé de UnixSocketServer, qui bloque : les deux écoutes doivent coexister.
func StartUIDAllocationServer() {
	logs.Go("service UID", UIDAllocationServer)
}
