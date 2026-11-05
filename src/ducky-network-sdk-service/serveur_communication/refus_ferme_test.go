package serveurcommunication

import (
	"bytes"
	"net"
	"testing"
	"time"

	"duckynetworkclient/V1/duckynetwork/sendmessage"
	"duckynetworkclient/V1/duckynetwork/storage"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"duckynetworkclient/V1/sessionmgr"
)

// Un refus d'authentification (02_07) FERME la session qu'il refuse — TO-DO 159.
//
// Ces tests jouent la boucle de réception entière, sur une vraie connexion et
// avec le chiffrement de session : la trame est émise comme le ferait le core,
// et l'on regarde ce que devient la connexion.
//
// # Ce qu'ils gardent
//
// La fermeture était un effet de bord : le gestionnaire paniquait en lisant un
// refus d'une ligne, et la récupération de la panique fermait. Un refus bien
// formé — deux lignes — ne paniquait pas, donc ne fermait RIEN : la session
// restait ouverte, jamais authentifiée, jusqu'au balayage du core.

// boucleSurUnTuyau lance handleConnection sur une extrémité d'un tuyau et rend
// de quoi écrire à l'autre comme le core.
func boucleSurUnTuyau(t *testing.T, id string, statut sessionmgr.SessionStatus) (ds, core *storage.DuckySession, fin chan struct{}) {
	t.Helper()
	coteCore, cotePoste := net.Pipe()
	cle := bytes.Repeat([]byte{7}, 32)

	ds = &storage.DuckySession{SessionID: id, Conn: cotePoste, IsSafe: true, SessionKey: cle}
	core = &storage.DuckySession{SessionID: id, Conn: coteCore, IsSafe: true, SessionKey: cle}
	stosession.SessionsUser.AddOrUpdate(id, "vaultaire", cotePoste, statut, ds)

	fin = make(chan struct{})
	go func() {
		handleConnection("vaultaire", ds)
		close(fin)
	}()
	t.Cleanup(func() {
		coteCore.Close()
		cotePoste.Close()
		stosession.SessionsUser.RemoveSession(id)
	})
	return ds, core, fin
}

func TestUnRefusFermeLaSessionRefusee(t *testing.T) {
	for _, cas := range []struct{ nom, trame, motif string }{
		// Core à jour : le compte, puis le motif. C'est la forme qui NE
		// paniquait PAS — donc celle qui laissait la session ouverte.
		{"deux-lignes", "02_07\nserveur_central\nCLE\nvaultaire\nYou are not authentificate", "You are not authentificate"},
		// Core antérieur à la 2.3 : le motif seul. Celle qui paniquait.
		{"une-ligne", "02_07\nserveur_central\nCLE\nWrong login Data", "Wrong login Data"},
	} {
		t.Run(cas.nom, func(t *testing.T) {
			id := "refus-" + cas.nom
			ds, core, fin := boucleSurUnTuyau(t, id, sessionmgr.SessionPending)

			go sendmessage.SendMessage(cas.trame, core)

			select {
			case <-fin:
			case <-time.After(5 * time.Second):
				t.Fatal("la boucle de réception tourne encore cinq secondes après le refus : la session n'est pas fermée")
			}
			if ds.Refus != cas.motif {
				t.Errorf("motif retenu %q, attendu %q", ds.Refus, cas.motif)
			}
			if _, encore := stosession.SessionsUser.GetBySessionID(id); encore {
				t.Error("la session refusée est toujours au registre")
			}
			// Le socket est fermé : le core lit la fin, pas un silence.
			core.Conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			if _, err := core.Conn.Read(make([]byte, 1)); err == nil {
				t.Error("le socket de la session refusée est encore ouvert")
			} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Error("le socket de la session refusée est encore ouvert (lecture en attente)")
			}
		})
	}
}

// Un core antérieur émet un 02_07 DANS le tunnel d'une machine quand une
// demande d'ouverture de session est malformée. Ce tunnel est authentifié :
// il doit survivre.
func TestUnRefusNeFermePasUnTunnelAuthentifie(t *testing.T) {
	ds, core, fin := boucleSurUnTuyau(t, "tunnel-authentifie", sessionmgr.SessionAuthenticated)

	envoye := make(chan struct{})
	go func() {
		sendmessage.SendMessage("02_07\nserveur_central\nCLE\nvaultaire\ninvalid request", core)
		// Une seconde trame : elle n'est lue que si la boucle tourne encore.
		sendmessage.SendMessage("02_07\nserveur_central\nCLE\nvaultaire\ninvalid request", core)
		close(envoye)
	}()

	select {
	case <-envoye:
	case <-fin:
		t.Fatal("le tunnel authentifié a été fermé par un refus qui n'était pas le sien")
	case <-time.After(5 * time.Second):
		t.Fatal("la seconde trame n'a pas été lue : la boucle de réception s'est arrêtée")
	}
	select {
	case <-fin:
		t.Fatal("le tunnel authentifié a été fermé après le refus")
	case <-time.After(200 * time.Millisecond):
	}
	if ds.Refus != "" {
		t.Errorf("le tunnel porte un motif de refus : %q", ds.Refus)
	}
	if statut, _ := stosession.SessionsUser.GetStatus(ds.SessionID); statut != sessionmgr.SessionAuthenticated {
		t.Errorf("le tunnel n'est plus authentifié au registre : %v", statut)
	}
}
