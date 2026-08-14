package decouverte

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/serveurauth"
)

// Découverte des nœuds joignables (trames 04_03 / 04_04).
//
// # Le problème
//
// La liste des serveurs d'un agent vivait dans son fichier de configuration, et
// nulle part ailleurs. Ajouter un core au cluster demandait de repasser sur
// chaque machine du parc ; en retirer un laissait les agents s'y acharner
// jusqu'à ce que quelqu'un édite le fichier.
//
// Un proxy déployé, lui, n'apparaissait dans aucune configuration — donc aucun
// agent n'y passait, donc il ne servait à rien.
//
// # Ce que ce paquet fait, et ce qu'il ne fait pas
//
// Il DEMANDE la liste et la FUSIONNE avec celle du fichier. Il ne choisit pas :
// l'ordre vient du serveur, qui seul voit le parc. Il ne se connecte à rien —
// l'établissement de session reste où il est.
//
// # Pourquoi la liste du fichier n'est jamais écrasée
//
// Elle est le dernier recours. Un agent qui remplacerait ses serveurs statiques
// par ceux reçus n'aurait plus rien à joindre le jour où la liste distribuée est
// vide, fausse, ou pointe sur des nœuds tous éteints — et il faudrait alors
// repasser à la main sur les machines, c'est-à-dire exactement ce que la
// découverte existe pour éviter.
//
// Les nœuds appris passent donc DEVANT, et les statiques restent en queue.

// Noeud est une adresse joignable, telle que le core l'annonce.
type Noeud struct {
	Hostname string
	IP       string
	Port     int
	Role     string
	Priorite int

	// Empreinte de la clé publique de ce nœud.
	//
	// C'est elle qui rend la découverte utilisable. Sans elle, l'agent
	// apprendrait une adresse et devrait accepter la clé de ce nœud en aveugle
	// à sa première connexion — c'est-à-dire faire exactement ce que le fichier
	// d'empreintes existe pour empêcher.
	Empreinte string
}

// Adresse rend « ip:port ».
func (n Noeud) Adresse() string { return n.IP + ":" + strconv.Itoa(n.Port) }

var (
	mu      sync.RWMutex
	appris  []Noeud
	recuUne bool
)

// Appris rend les nœuds découverts, dans l'ordre servi par le core.
func Appris() []Noeud {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Noeud, len(appris))
	copy(out, appris)
	return out
}

// AJamaisRecuDeListe dit si aucune 04_04 n'est encore arrivée.
//
// Sert à distinguer « le core n'annonce aucun nœud » de « on n'a pas encore
// demandé ». Les deux donnent une liste vide, et les confondre ferait
// journaliser une alerte au démarrage de chaque agent.
func AJamaisRecuDeListe() bool {
	mu.RLock()
	defer mu.RUnlock()
	return !recuUne
}

// ConstruireDemande compose la trame 04_03.
//
// Contenu VIDE : le core lit l'identifiant de la machine dans l'en-tête, où la
// couche de session l'a posé — donc authentifié. Le mettre dans le contenu
// laisserait n'importe quel client réclamer la vue d'un autre.
func ConstruireDemande(sessionKey, clientID string) string {
	return strings.Join([]string{
		"04_03", "serveur_central", sessionKey, "vaultaire", clientID,
	}, "\n")
}

// AnalyserListe lit le contenu d'une 04_04.
//
//	<nombre>
//	<hostname>|<ip>|<port>|<role>|<priorite>|<empreinte>
//	…
//
// # Pourquoi le nombre annoncé est VÉRIFIÉ et non cru
//
// Il est la première ligne, et il serait tentant de s'en servir pour découper.
// Mais une trame tronquée — coupure, réassemblage incomplet — annoncerait dix
// nœuds et n'en porterait que trois. Les lignes font foi ; le nombre sert à
// détecter l'écart et à le dire.
func AnalyserListe(contenu string) ([]Noeud, error) {
	lignes := strings.Split(strings.TrimSpace(contenu), "\n")
	if len(lignes) == 0 || strings.TrimSpace(lignes[0]) == "" {
		return nil, fmt.Errorf("04_04 vide")
	}

	annonce, err := strconv.Atoi(strings.TrimSpace(lignes[0]))
	if err != nil {
		return nil, fmt.Errorf("04_04 : nombre de nœuds illisible (%q)", lignes[0])
	}

	var out []Noeud
	var rejetees int
	for _, ligne := range lignes[1:] {
		ligne = strings.TrimSpace(ligne)
		if ligne == "" {
			continue
		}
		n, err := analyserLigne(ligne)
		if err != nil {
			// Une ligne fautive n'emporte pas les autres : mieux vaut une liste
			// partielle qu'aucune liste. Mais elle est dite — elle signifie que
			// le core a annoncé quelque chose que l'agent refuse d'utiliser.
			logs.Write_log("WARNING", fmt.Sprintf("04_04 : ligne rejetée : %v", err))
			rejetees++
			continue
		}
		out = append(out, n)
	}

	if annonce != len(out)+rejetees {
		logs.Write_log("WARNING", fmt.Sprintf(
			"04_04 : %d nœud(s) annoncé(s), %d ligne(s) reçue(s) — trame probablement "+
				"tronquée, la liste retenue est partielle", annonce, len(out)+rejetees))
	}
	return out, nil
}

func analyserLigne(ligne string) (Noeud, error) {
	champs := strings.Split(ligne, "|")
	if len(champs) != 6 {
		return Noeud{}, fmt.Errorf("%q : 6 champs attendus, %d reçus", ligne, len(champs))
	}

	port, err := strconv.Atoi(strings.TrimSpace(champs[2]))
	if err != nil || port < 1 || port > 65535 {
		return Noeud{}, fmt.Errorf("%q : port invalide", ligne)
	}
	ip := strings.TrimSpace(champs[1])
	if ip == "" {
		return Noeud{}, fmt.Errorf("%q : adresse vide", ligne)
	}
	role := strings.TrimSpace(champs[3])
	if role != "core" && role != "proxy" {
		// Fail-closed. Un rôle inconnu vient d'un core plus récent ; s'y
		// connecter reviendrait à traiter comme un serveur d'authentification
		// quelque chose dont on ignore la nature.
		return Noeud{}, fmt.Errorf("%q : rôle %q inconnu de cet agent", ligne, role)
	}
	priorite, _ := strconv.Atoi(strings.TrimSpace(champs[4]))

	// L'EMPREINTE est obligatoire. Un nœud annoncé sans elle serait une adresse
	// qu'on ne saurait pas reconnaître : s'y connecter reviendrait à accepter la
	// première clé venue, ce que le fichier d'empreintes existe pour empêcher.
	//
	// Le core l'écarte déjà à l'émission ; on le refait ici. C'est le même
	// principe que partout ailleurs sur ce chemin — le core est authentifié, il
	// n'est pas infaillible, et ce qui est en jeu est ce que la machine acceptera
	// comme serveur.
	empreinte := strings.TrimSpace(champs[5])
	if !strings.HasPrefix(empreinte, "SHA256:") {
		return Noeud{}, fmt.Errorf("%q : empreinte absente ou de forme inattendue", ligne)
	}

	return Noeud{
		Hostname:  strings.TrimSpace(champs[0]),
		IP:        ip,
		Port:      port,
		Role:      role,
		Priorite:  priorite,
		Empreinte: empreinte,
	}, nil
}

// Enregistrer retient la liste reçue.
//
// # L'ordre n'est PAS retrié
//
// Il vient du serveur, qui seul voit le parc — qui est en ligne, qui est chargé,
// qui vient de redémarrer. Le retrier ici substituerait la vue d'un agent à
// celle du cluster, et chaque agent le ferait avec SA version du code : changer
// la règle demanderait de mettre le parc à jour avant qu'elle prenne effet.
//
// # Une liste vide n'écrase pas une liste pleine
//
// Un core qui répond « aucun nœud » a peut-être une base indisponible, ou une
// migration de schéma qui vient de passer sans qu'aucun nœud ne se soit
// réenregistré. Effacer sur cette foi couperait l'agent de tout ce qu'il avait
// appris, au moment précis où le core va mal.
func Enregistrer(noeuds []Noeud) {
	mu.Lock()
	defer mu.Unlock()

	recuUne = true
	if len(noeuds) == 0 {
		if len(appris) > 0 {
			logs.Write_log("WARNING",
				"04_04 : le core n'annonce aucun nœud — la liste apprise est conservée")
		}
		return
	}
	appris = noeuds
}

// ApprendreEmpreintes retient les empreintes des nœuds annoncés.
//
// # Pourquoi c'est légitime, et où est la limite
//
// L'empreinte arrive dans le MÊME message que l'adresse qu'elle atteste. Prise
// isolément, cette réponse n'atteste donc rien : qui peut composer la liste peut
// composer les deux.
//
// Ce qui la rend valable est le canal. La 04_04 arrive sur une session dont la
// clé du core a DÉJÀ été vérifiée contre une empreinte connue de cette machine.
// Ce n'est pas un nœud qui s'atteste lui-même — c'est un core de confiance qui
// atteste ses pairs. La confiance s'étend depuis une confiance existante, ce qui
// est exactement l'arbitrage 3.
//
// LA LIMITE EST ASSUMÉE ET ÉCRITE : tout core de confiance peut ajouter de la
// confiance. Un core compromis fait apprendre au parc l'empreinte de son choix.
// Ce qui borne le risque est ailleurs — un core compromis détient déjà les clés
// du domaine, et l'empreinte n'est pas ce qui le retient.
//
// # Pourquoi les échecs ne sont pas fatals
//
// `ApprendreEmpreinte` refuse quand la machine n'a aucune empreinte de
// référence : elle est alors en confiance au premier usage, et il n'y a pas de
// confiance à étendre. Ce n'est pas une anomalie — c'est l'état d'un agent
// installé sans `-join`, et la liste reste utilisable pour le nœud qu'il joint
// déjà.
func ApprendreEmpreintes(noeuds []Noeud) {
	var appris int
	for _, n := range noeuds {
		ok, err := serveurauth.ApprendreEmpreinte(n.Empreinte)
		if err != nil {
			logs.Write_log("WARNING", fmt.Sprintf(
				"04_04 : empreinte de %s non retenue : %v", n.Hostname, err))
			// Le premier refus vaut pour tous — liste vide, ou borne atteinte.
			// Insister produirait la même ligne autant de fois qu'il y a de
			// nœuds, et noierait le motif.
			return
		}
		if ok {
			appris++
			logs.Write_log("INFO", fmt.Sprintf(
				"04_04 : empreinte de %s (%s) apprise du core courant", n.Hostname, n.Empreinte))
		}
	}
	if appris > 0 {
		logs.Write_log("INFO", fmt.Sprintf(
			"04_04 : %d empreinte(s) ajoutée(s) à la liste de confiance", appris))
	}
}

// FusionnerAdresses compose la liste d'adresses à essayer.
//
// Les nœuds APPRIS d'abord, dans l'ordre du core ; les STATIQUES ensuite, ceux
// qui ne font pas déjà doublon. Aucun tri : l'ordre des deux sources est
// signifiant, et les mélanger le détruirait.
//
// Rend des chaînes « ip:port » plutôt que des structures : c'est ce dont
// l'établissement de session a besoin, et lui passer des types du paquet
// l'obligerait à en dépendre.
func FusionnerAdresses(statiques []string) []string {
	apprises := Appris()

	out := make([]string, 0, len(apprises)+len(statiques))
	vues := map[string]bool{}

	for _, n := range apprises {
		a := n.Adresse()
		if vues[a] {
			continue
		}
		vues[a] = true
		out = append(out, a)
	}
	for _, a := range statiques {
		a = strings.TrimSpace(a)
		if a == "" || vues[a] {
			continue
		}
		vues[a] = true
		out = append(out, a)
	}
	return out
}

// Resume rend une ligne lisible pour le journal.
//
// Trié par nom, uniquement pour l'affichage : deux journaux successifs sur un
// même état doivent se comparer à l'œil. L'ordre d'ESSAI, lui, n'est jamais
// touché — voir Enregistrer.
func Resume() string {
	noeuds := Appris()
	if len(noeuds) == 0 {
		return "aucun nœud appris"
	}
	descriptions := make([]string, 0, len(noeuds))
	for _, n := range noeuds {
		descriptions = append(descriptions, n.Role+" "+n.Hostname+" ("+n.Adresse()+")")
	}
	sort.Strings(descriptions)
	return strings.Join(descriptions, ", ")
}

// EmpreintesConnues rend le nombre d'empreintes de confiance sur cette machine.
//
// Sert au journal de démarrage : un agent qui apprend des cores sans avoir
// d'empreinte les refusera tous, et la ligne le dit avant qu'on cherche
// ailleurs.
func EmpreintesConnues() int {
	liste, err := serveurauth.EmpreintesAttendues()
	if err != nil {
		return 0
	}
	return len(liste)
}
