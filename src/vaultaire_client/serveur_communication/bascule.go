package serveurcommunication

import (
	"fmt"
	"strings"

	"duckynetworkclient/V1/duckynetwork/decouverte"
	"duckynetworkclient/V1/duckynetwork/logs"
	"duckynetworkclient/V1/duckynetwork/storage/stosession"
	"vaultaire_client/serveur_communication/module"
)

// Bascule vers le nœud prioritaire, à la réception d'une nouvelle liste.
//
// # Le défaut que cela corrige
//
// L'agent se connecte au premier nœud qui répond, dans l'ordre servi par le
// core. Cet ordre est calculé une fois, à la connexion. Si un nœud plus
// prioritaire est ajouté, remis en ligne ou repriorisé ensuite, l'agent
// continue de parler à celui qu'il tient — jusqu'au prochain redémarrage.
//
// Un poste peut donc rester des semaines sur un nœud de secours alors que le
// nœud principal est revenu, sans que rien ne le signale : de son point de vue
// tout fonctionne.
//
// # Ce que la bascule fait, et ne fait pas
//
// Elle ne CHOISIT pas de nœud : elle ferme la session courante, et la
// supervision du tunnel rétablit la connexion par le chemin ordinaire, qui
// essaie les adresses dans l'ordre servi par le core. Rejouer ici une logique
// de sélection en aurait fait une seconde, à tenir d'accord avec la première.
//
// # L'égalité ne bascule pas
//
// Deux nœuds de même priorité sont équivalents : basculer de l'un vers l'autre
// ne gagne rien et coûte une coupure. Pire, sur un parc où deux nœuds se
// disputent la tête de liste, chaque nouvelle 04_04 provoquerait une
// reconnexion — un va-et-vient permanent déclenché par le mécanisme censé
// améliorer les choses. La bascule n'a lieu que si le nœud courant est
// STRICTEMENT moins prioritaire que le meilleur disponible.

// ArmerBascule branche la bascule sur l'arrivée d'une nouvelle liste.
//
// À appeler une fois, au démarrage, après decouverte.Configure.
func ArmerBascule() {
	decouverte.SurNouvelleListe(func(noeuds []decouverte.Noeud) {
		EvaluerBascule(noeuds, module.Etat().Adresse)
	})
}

// EvaluerBascule décide, et bascule si nécessaire.
//
// `courante` est l'adresse « ip:port » en cours d'usage. Exportée avec la
// décision séparée de l'action pour être éprouvable sans tunnel.
func EvaluerBascule(noeuds []decouverte.Noeud, courante string) {
	raison, basculer := DecisionDeBascule(noeuds, courante)
	if !basculer {
		if raison != "" {
			logs.Write_log("DEBUG", "bascule : "+raison)
		}
		return
	}

	logs.Write_log("INFO", "bascule : "+raison)
	fermerTunnelMachine()
}

// DecisionDeBascule dit s'il faut basculer, et pourquoi.
//
// Rend (explication, faut-il basculer). L'explication est renseignée dans les
// deux cas : savoir POURQUOI on ne bascule pas est ce qu'on cherchera le jour
// où l'on croira qu'on aurait dû.
func DecisionDeBascule(noeuds []decouverte.Noeud, courante string) (string, bool) {
	courante = strings.TrimSpace(courante)
	if courante == "" {
		return "", false // aucun tunnel établi : rien à quitter
	}
	if len(noeuds) == 0 {
		// Une liste vide ne signifie pas que le nœud courant est mauvais : elle
		// signifie qu'on ne sait rien. Basculer sur cette base couperait le
		// tunnel pour se reconnecter au même endroit, ou à rien.
		return "liste vide, le nœud courant est conservé", false
	}

	// La priorité du nœud COURANT, telle que le core vient de l'annoncer.
	// Absent de la liste : il a été retiré ou n'est plus joignable, et c'est
	// justement le cas où il faut partir.
	prioriteCourante, present := prioriteDe(noeuds, courante)
	if !present {
		return fmt.Sprintf("le nœud courant %s ne figure plus dans la liste servie par le core",
			courante), true
	}

	meilleur, prioriteMeilleure := meilleurNoeud(noeuds)
	if prioriteCourante <= prioriteMeilleure {
		return fmt.Sprintf("le nœud courant %s est déjà au meilleur rang (priorité %d)",
			courante, prioriteCourante), false
	}

	return fmt.Sprintf("le nœud courant %s est de priorité %d, %s est à %d — reconnexion",
		courante, prioriteCourante, meilleur, prioriteMeilleure), true
}

// prioriteDe rend la priorité effective d'une adresse dans la liste.
func prioriteDe(noeuds []decouverte.Noeud, adresse string) (int, bool) {
	for _, n := range noeuds {
		if n.Adresse() == adresse {
			return prioriteEffective(n.Priorite), true
		}
	}
	return 0, false
}

// meilleurNoeud rend l'adresse et la priorité du meilleur nœud de la liste.
func meilleurNoeud(noeuds []decouverte.Noeud) (string, int) {
	meilleur := noeuds[0].Adresse()
	priorite := prioriteEffective(noeuds[0].Priorite)
	for _, n := range noeuds[1:] {
		if p := prioriteEffective(n.Priorite); p < priorite {
			meilleur, priorite = n.Adresse(), p
		}
	}
	return meilleur, priorite
}

// prioriteEffective traduit « 0 ou moins » en « dernier ».
//
// C'est la convention du core (voir cluster_database.prioriteEffective) : une
// priorité non renseignée passe en queue plutôt qu'en tête. La reprendre ici
// évite qu'un nœud sans priorité déclarée paraisse meilleur que tous les
// autres et provoque une bascule permanente vers lui.
func prioriteEffective(p int) int {
	if p <= 0 {
		return 1 << 30
	}
	return p
}

// fermerTunnelMachine coupe la session mère pour forcer une reconnexion.
//
// Par RemoveSession et non par un Conn.Close() direct : c'est le geste déjà
// employé ailleurs dans ce paquet, et il évite de fermer une connexion
// différente si un rétablissement a eu lieu entre-temps. La supervision
// (DemarrerTunnelMachine) relance ensuite la boucle, qui reprend la liste au
// début.
var fermerTunnelMachine = func() {
	session := stosession.SessionsUser.GetValidVaultaireSession()
	if session == nil || session.DuckySession == nil {
		logs.Write_log("WARNING", "bascule : aucun tunnel machine à fermer")
		return
	}
	stosession.SessionsUser.RemoveSession(session.DuckySession.SessionID)
	logs.Write_log("INFO", "bascule : tunnel machine fermé, la supervision va rouvrir sur le nœud prioritaire")
}
