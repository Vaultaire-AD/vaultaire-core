//go:build windows

package ipc

import (
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"duckynetworkclient/V1/duckynetwork/logs"
)

// Le serveur de tube nommé.
//
// # La liste de contrôle d'accès, et pourquoi elle est écrite ici
//
// Un tube nommé créé sans descripteur de sécurité hérite du jeton de son
// créateur : l'agent tourne en SYSTEM, le tube serait donc ouvert à peu près à
// tout le monde en lecture. Or le mot de passe en clair de chaque ouverture de
// session y passe.
//
// Le descripteur ci-dessous n'accorde l'accès qu'à SYSTEM et aux
// administrateurs de la machine. C'est exactement la décision prise pour le
// socket PAM de l'agent Linux : un répertoire 0700 et un refus de tout appelant
// non root.
//
//	D:P             liste discrétionnaire, PROTÉGÉE (aucun héritage du parent)
//	(A;;GA;;;SY)    tout accès, compte SYSTEM
//	(A;;GA;;;BA)    tout accès, groupe Administrateurs
//
// LogonUI.exe, qui charge le Credential Provider, tourne en SYSTEM : il entre.
// Un utilisateur ordinaire du poste, non.
const sddlTube = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"

// Tailles des tampons du tube. Petites à dessein : les messages sont de
// quelques centaines d'octets, et un tampon large ne ferait que réserver de la
// mémoire non paginée du noyau.
const (
	tamponEntree = 4096
	tamponSortie = 4096
	// instancesMax : plusieurs sessions Windows (utilisateur rapide, bureau à
	// distance) peuvent demander une authentification en même temps.
	instancesMax = 16
	// delaiDefautMs est le délai d'attente par défaut d'un client, en
	// millisecondes. Il ne borne PAS nos lectures : celles-là ont leur propre
	// échéance, posée sur la connexion.
	delaiDefautMs = 5000
)

// Traitement répond à une requête. Signature volontairement close : ce qui
// répond n'a aucune raison de connaître le tube.
type Traitement func(Requete) Reponse

// Serveur écoute le tube nommé.
type Serveur struct {
	traiter Traitement
	// DelaiRequete borne la vie d'UNE connexion, lecture et réponse comprises.
	DelaiRequete time.Duration

	arrete  atomic.Bool
	servies atomic.Int64
	refusee atomic.Int64
}

// DelaiRequeteParDefaut : au-delà, la connexion est fermée.
//
// Plus long que le délai d'authentification côté agent (7 s) : le traitement
// doit avoir le temps de rendre son verdict, sinon le Credential Provider
// verrait une connexion coupée là où il y a un refus.
const DelaiRequeteParDefaut = 20 * time.Second

// NouveauServeur prépare le serveur. Rien n'est créé avant Servir.
func NouveauServeur(traiter Traitement) *Serveur {
	return &Serveur{traiter: traiter, DelaiRequete: DelaiRequeteParDefaut}
}

// Servir crée le tube et boucle sur les connexions. Ne rend la main que sur
// erreur fatale ou après Arreter.
//
// # Une instance de tube par connexion
//
// Une instance de tube nommé ne sert qu'UN client à la fois. On en crée donc
// une nouvelle à chaque tour de boucle, et la précédente vit le temps de sa
// requête dans sa propre goroutine. Servir en séquence ferait attendre une
// seconde session derrière une authentification lente — c'est-à-dire, sur un
// serveur de rebond, derrière le délai réseau d'un autre utilisateur.
func (s *Serveur) Servir() error {
	sd, err := windows.SecurityDescriptorFromString(sddlTube)
	if err != nil {
		return fmt.Errorf("descripteur de sécurité du tube illisible : %w", err)
	}
	sa := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}

	nom, err := windows.UTF16PtrFromString(NomTube)
	if err != nil {
		return err
	}

	logs.Write_log("INFO", "canal du Credential Provider : "+NomTube)

	for !s.arrete.Load() {
		tube, err := windows.CreateNamedPipe(nom,
			windows.PIPE_ACCESS_DUPLEX,
			windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT,
			instancesMax, tamponSortie, tamponEntree, delaiDefautMs, &sa)
		if err != nil {
			return fmt.Errorf("création du tube %s : %w", NomTube, err)
		}

		// ConnectNamedPipe rend ERROR_PIPE_CONNECTED quand un client s'est
		// connecté entre la création et l'appel : ce n'est pas une erreur, le
		// client est là.
		if err := windows.ConnectNamedPipe(tube, nil); err != nil && err != windows.ERROR_PIPE_CONNECTED {
			_ = windows.CloseHandle(tube)
			if s.arrete.Load() {
				return nil
			}
			logs.Write_log("WARNING", fmt.Sprintf("canal : attente de connexion échouée : %v", err))
			continue
		}

		go s.servirUne(tube)
	}
	return nil
}

// Arreter demande l'arrêt. La boucle sort au tour suivant.
func (s *Serveur) Arreter() { s.arrete.Store(true) }

// Stats rend (requêtes servies, requêtes refusées).
func (s *Serveur) Stats() (int64, int64) { return s.servies.Load(), s.refusee.Load() }

func (s *Serveur) servirUne(tube windows.Handle) {
	defer func() {
		// Vider avant de fermer : sans cela, la fermeture peut détruire la
		// réponse que le client n'a pas encore lue — il verrait une connexion
		// coupée là où il y a un verdict.
		_ = windows.FlushFileBuffers(tube)
		_ = windows.DisconnectNamedPipe(tube)
		_ = windows.CloseHandle(tube)
		if r := recover(); r != nil {
			logs.Write_log("CRITICAL", fmt.Sprintf("canal : panique pendant une requête : %v", r))
		}
	}()

	// Le VEILLEUR : une lecture sur un tube nommé bloque sans limite, et un
	// client qui ouvre le tube sans rien dire immobiliserait cette goroutine
	// pour toujours. CancelIoEx débloque la lecture en cours ; c'est la seule
	// façon d'imposer une échéance sans passer le tube en mode asynchrone, qui
	// ferait entrer une machine à états complète pour deux lectures.
	veilleur := time.AfterFunc(s.DelaiRequete, func() {
		_ = windows.CancelIoEx(tube, nil)
	})
	defer veilleur.Stop()

	conn := &connexionTube{tube: tube, fin: time.Now().Add(s.DelaiRequete)}

	req, err := LireRequete(conn)
	if err != nil {
		s.refusee.Add(1)
		logs.Write_log("WARNING", "canal : "+err.Error())
		_ = EcrireReponse(conn, Reponse{Statut: StatutRefus, Message: "requête illisible"})
		return
	}
	// Le mot de passe ne survit pas à la requête, même si la réponse échoue.
	defer func() { req.MotDePasse = "" }()

	if err := ValiderRequete(req); err != nil {
		s.refusee.Add(1)
		// Le nom est journalisé, le mot de passe JAMAIS — pas même sa longueur.
		logs.Write_log("WARNING", fmt.Sprintf("canal : requête refusée pour %q : %v", req.Utilisateur, err))
		_ = EcrireReponse(conn, Reponse{Statut: StatutRefus, Message: "requête invalide"})
		return
	}

	s.servies.Add(1)

	// Le traitement est BORNÉ lui aussi. Le veilleur ci-dessus ne débloque que
	// les lectures ; un traitement qui s'éterniserait laisserait l'écran de
	// connexion attendre sans rien afficher. Une réponse « le core n'a pas
	// répondu » vaut mieux qu'une tuile figée.
	resultat := make(chan Reponse, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logs.Write_log("CRITICAL", fmt.Sprintf("canal : panique dans le traitement : %v", r))
				resultat <- Reponse{Statut: StatutRefus, Message: "erreur interne de l'agent"}
			}
		}()
		resultat <- s.traiter(req)
	}()

	var rep Reponse
	select {
	case rep = <-resultat:
	case <-time.After(s.DelaiRequete):
		logs.Write_log("ERROR", fmt.Sprintf(
			"canal : traitement non terminé en %s pour %q", s.DelaiRequete, req.Utilisateur))
		rep = Reponse{Statut: StatutDelai, Message: "le service n'a pas répondu à temps"}
	}

	if err := EcrireReponse(conn, rep); err != nil {
		logs.Write_log("WARNING", fmt.Sprintf("canal : réponse non transmise pour %q : %v", req.Utilisateur, err))
	}
}

// connexionTube donne un io.ReadWriter borné dans le temps au-dessus du handle.
//
// Pas de net.Conn : les tubes nommés de Windows n'en sont pas, et les
// échéances se posent ici, à la main. Sans échéance, un client qui ouvre le
// tube et ne dit rien immobilise une goroutine pour toujours.
type connexionTube struct {
	tube windows.Handle
	fin  time.Time
}

func (c *connexionTube) Read(p []byte) (int, error) {
	if time.Now().After(c.fin) {
		return 0, fmt.Errorf("délai de lecture dépassé")
	}
	var lus uint32
	if err := windows.ReadFile(c.tube, p, &lus, nil); err != nil {
		return int(lus), err
	}
	return int(lus), nil
}

func (c *connexionTube) Write(p []byte) (int, error) {
	var ecrits uint32
	if err := windows.WriteFile(c.tube, p, &ecrits, nil); err != nil {
		return int(ecrits), err
	}
	return int(ecrits), nil
}

// Contrôle de compilation : connexionTube doit rester un simple io.ReadWriter.
var _ interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
} = (*connexionTube)(nil)
