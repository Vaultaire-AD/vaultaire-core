package revocationmanager

import (
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/logs"
	"vaultaire/core/revocation"
	"vaultaire/ducky-network/sendmessage"
	"vaultaire/ducky-network/sessionmgr"
)

// Le core rejoue lui-même les ordres non acquittés — TO-DO 49.
//
// # Ce qui manquait
//
// Un ordre était poussé UNE fois, au déclenchement, aux machines connectées.
// Ensuite le core attendait qu'on vienne le lui redemander (06_04). Or :
//
//   - un envoi peut échouer sur une machine pourtant connectée ;
//   - depuis le 133 un ordre peut ÉCHOUER pour de bon — des processus qui ne
//     meurent pas — et le core écrivait « sera rejoué » sans rien rejouer ;
//   - une machine qui se connecte à un AUTRE core du cluster que celui où la
//     commande a été tapée ne recevait rien du tout avant de le demander.
//
// Le point 134 a borné cette attente à dix minutes, du côté de l'agent. Elle
// restait entière pour un agent antérieur, qui ne redemande qu'à son démarrage,
// et dix minutes sont longues pour un compte qu'on vient de couper.
//
// # Ce que fait cette boucle
//
// Toutes les PasDuRejeu, pour chaque machine CONNECTÉE À CE CORE à qui il reste
// un ordre à remettre : si l'un d'eux est dû, la liste entière repart, dans
// l'ordre. Chaque core sert ses propres machines ; la base est commune, donc un
// ordre tapé sur un nœud atteint en quelques secondes une machine tenue par un
// autre.
//
// # La liste entière, et par une 06_05
//
// L'ordre chronologique n'est pas négociable : un verrouillage puis sa levée,
// rejoués à l'envers, laissent la machine fermée. Remettre le seul ordre « dû »
// en sautant un plus ancien qui ne l'est pas encore casserait cela. Une machine
// due reçoit donc TOUT ce qu'elle n'a pas acquitté, dans une seule trame 06_05 —
// la liste que l'agent applique déjà dans l'ordre, qu'il l'ait demandée ou non.
// Plusieurs 06_01 à la suite auraient dépendu de l'ordre d'arrivée.
//
// Rejouer un ordre déjà appliqué est sans effet : l'agent s'en souvient
// (AlreadyApplied) et se contente de ré-acquitter.
//
// # L'espacement
//
// Dix secondes après le premier envoi, puis le double à chaque essai, plafonné
// à cinq minutes. Un envoi perdu est rattrapé vite ; une machine qui échoue
// durablement — ou qui n'applique pas les ordres du tout, comme le client
// Windows V1 (TO-DO 79) — n'est pas sollicitée toutes les cinq secondes pour
// rien. Il n'y a PAS d'abandon : un kill switch qui renonce au bout de N essais
// laisse un compte ouvert sans le dire.

const (
	// PasDuRejeu est l'intervalle entre deux tours. C'est aussi le délai au bout
	// duquel une machine qui vient de se connecter reçoit ce qui l'attend, si
	// elle ne l'a pas demandé elle-même.
	PasDuRejeu = 5 * time.Second
	// PremierRejeu est l'attente après le premier envoi. Plus longue que le
	// temps laissé par l'agent aux processus pour mourir (cinq secondes) : on
	// ne rejoue pas un ordre que la machine est encore en train d'appliquer.
	PremierRejeu = 10 * time.Second
	// PlafondDuRejeu borne l'espacement. Sous les dix minutes du rappel de
	// l'agent : le core reste le plus rapide des deux.
	PlafondDuRejeu = 5 * time.Minute

	// essaisBavards : au-delà, les rejeux d'une machine passent en DEBUG. Une
	// machine qui ne répond jamais écrirait sinon une ligne toutes les cinq
	// minutes, pour toujours, dans un journal qu'on lit pendant les incidents.
	essaisBavards = 5
)

// attenteApres rend le temps à laisser passer après le n-ième essai.
func attenteApres(essais int) time.Duration {
	if essais <= 0 {
		return 0
	}
	attente := PremierRejeu
	for i := 1; i < essais; i++ {
		attente *= 2
		if attente >= PlafondDuRejeu {
			return PlafondDuRejeu
		}
	}
	return attente
}

// estDu dit si un ordre en attente doit être remis maintenant.
//
// Pure : c'est la décision « ce compte reste-t-il ouvert un tour de plus », et
// elle s'éprouve sans base ni horloge.
func estDu(e dbrevocation.EnAttente) bool {
	if e.Essais <= 0 || !e.DepuisLeDernier.Valid {
		// Jamais remis : la machine était absente au déclenchement, ou l'envoi
		// a échoué. Rien à attendre.
		return true
	}
	return time.Duration(e.DepuisLeDernier.Int64)*time.Second >= attenteApres(e.Essais)
}

// sourceDuRejeu réunit ce dont un tour a besoin. Des fonctions, pour qu'un test
// joue un tour entier sans base ni réseau.
type sourceDuRejeu struct {
	connectees        func() []string
	machinesEnAttente func() ([]string, error)
	enAttentePour     func(computeurID string) ([]dbrevocation.EnAttente, error)
	remettre          func(computeurID string, ordres []revocation.Order) bool
	noter             func(computeurID string, ids []int)
}

// unTourDeRejeu fait un passage et rend le nombre de machines servies.
func unTourDeRejeu(src sourceDuRejeu) int {
	connectees := src.connectees()
	if len(connectees) == 0 {
		// Aucune machine sur ce core : pas même une requête.
		return 0
	}
	enAttente, err := src.machinesEnAttente()
	if err != nil {
		logs.Write_Log("ERROR", "revocation: rejeu — lecture des machines en attente échouée : "+err.Error())
		return 0
	}
	if len(enAttente) == 0 {
		return 0
	}

	// La base compare les identifiants sans la casse ; le registre des sessions
	// garde celle qu'annonce la machine. On rapproche comme la base.
	ici := make(map[string]string, len(connectees))
	for _, id := range connectees {
		ici[strings.ToLower(strings.TrimSpace(id))] = id
	}

	servies := 0
	for _, machine := range enAttente {
		id, connectee := ici[strings.ToLower(strings.TrimSpace(machine))]
		if !connectee {
			continue
		}
		ordres, err := src.enAttentePour(machine)
		if err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf(
				"revocation: rejeu — ordres de %s illisibles : %v", machine, err))
			continue
		}
		dus, essaisMax := 0, 0
		for _, e := range ordres {
			if estDu(e) {
				dus++
			}
			if e.Essais > essaisMax {
				essaisMax = e.Essais
			}
		}
		if dus == 0 {
			continue
		}

		liste := make([]revocation.Order, len(ordres))
		ids := make([]int, len(ordres))
		for i, e := range ordres {
			liste[i], ids[i] = e.Ordre, e.Ordre.ID
		}
		if !src.remettre(id, liste) {
			// Pas d'essai inscrit : rien n'est parti, le tour suivant réessaie.
			continue
		}
		src.noter(machine, ids)
		servies++

		niveau := "INFO"
		if essaisMax >= essaisBavards {
			niveau = "DEBUG"
		}
		logs.Write_Log(niveau, fmt.Sprintf(
			"revocation: %d ordre(s) non acquitté(s) rejoué(s) vers %s (%d dû(s), essai %d)",
			len(liste), machine, dus, essaisMax+1))
		if essaisMax+1 == essaisBavards {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"revocation: %s n'a toujours pas acquitté après %d essais — le rejeu continue toutes les %s, "+
					"sans plus l'écrire à ce niveau. « vlt kill -u <compte> » n'est PAS effectif sur cette machine.",
				machine, essaisBavards, PlafondDuRejeu))
		}
	}
	return servies
}

// remettreLaListe envoie à une machine la liste de ses ordres en attente.
//
// Même choix de session que la poussée initiale (TO-DO 89) : le tunnel de la
// machine, le plus frais puis le plus ancien, jusqu'au premier envoi qui passe.
func remettreLaListe(computeurID string, ordres []revocation.Order) bool {
	for _, sess := range sessionmgr.Sessions.SessionsMachine(computeurID, sessionmgr.FraicheurTunnel()) {
		msg := buildListFrame(sess.SessionID, ordres)
		if err := sendmessage.SendMessage(msg, sess.ClientSoftwareID, sess.DuckySession); err != nil {
			logs.Write_Log("WARNING", fmt.Sprintf(
				"revocation: rejeu non remis à %s par la session %s : %v",
				computeurID, sess.SessionID, err))
			continue
		}
		return true
	}
	return false
}

// noterLEssai inscrit en base que des ordres viennent d'être remis.
//
// Un échec d'écriture ne retient rien : l'ordre est parti. Il fera seulement
// rejouer plus tôt que prévu — c'est le côté où il vaut mieux se tromper.
func noterLEssai(computeurID string, ids []int) {
	db := database.GetDatabase()
	if db == nil {
		return
	}
	if err := dbrevocation.NoterEssai(db, computeurID, ids); err != nil {
		logs.Write_Log("WARNING", "revocation: essai non inscrit pour "+computeurID+" : "+err.Error())
	}
}

// RejouerLesOrdres est la boucle de fond. Ne rend jamais la main : à lancer
// dans une goroutine, une fois le serveur Ducky démarré.
func RejouerLesOrdres() {
	src := sourceDuRejeu{
		connectees: func() []string { return sessionmgr.Sessions.MachinesConnectees() },
		machinesEnAttente: func() ([]string, error) {
			db := database.GetDatabase()
			if db == nil {
				return nil, fmt.Errorf("base indisponible")
			}
			return dbrevocation.MachinesEnAttente(db)
		},
		enAttentePour: func(computeurID string) ([]dbrevocation.EnAttente, error) {
			db := database.GetDatabase()
			if db == nil {
				return nil, fmt.Errorf("base indisponible")
			}
			return dbrevocation.EnAttentePour(db, computeurID, maxOrdersPerFrame)
		},
		remettre: remettreLaListe,
		noter:    noterLEssai,
	}
	logs.Write_Log("INFO", fmt.Sprintf(
		"revocation: rejeu des ordres non acquittés armé (tour toutes les %s, essais espacés de %s à %s)",
		PasDuRejeu, PremierRejeu, PlafondDuRejeu))
	for {
		time.Sleep(PasDuRejeu)
		unTourDeRejeu(src)
	}
}
