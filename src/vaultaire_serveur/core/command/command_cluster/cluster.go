package commandcluster

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
)

// Cluster_Command donne une vue de l'état du cluster.
//
//	cluster list                  tous les nœuds
//	cluster list <role>           nœuds actifs d'un rôle
//	cluster purge-delay           lit le délai de purge
//	cluster purge-delay <heures>  le règle
//	cluster metrics-retention          lit la rétention des métriques
//	cluster metrics-retention <jours>  la règle
//	cluster expose <noeud> <adr> [port]  déclare par où les agents le joignent
//	cluster priority <noeud> <valeur>    ordre de service
//	cluster rotation <noeud> <in|out>    annonce ce nœud aux agents, ou non
//	cluster affinity <noeud> <groupe...> groupes servis en priorité
//
// # Deux droits nouveaux, et pourquoi
//
// La commande empruntait `read:get:client` et `write:update:client` sur « * ».
// Voir l'état du cluster exigeait donc le droit de lire TOUTES les machines de
// TOUS les domaines, et régler le délai de purge emportait celui de les
// modifier. Deux responsabilités très différentes portées par la même clé.
//
// Elle exige maintenant `read:cluster` et `write:cluster`. Ces clés ne sont
// accordées à personne tant qu'on ne les accorde pas : après mise à jour, la
// commande répond « permission refusée » en nommant la clé manquante.
func Cluster_Command(args []string, sender_groupsIDs []int, sender_Username string) string {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return aide()
	}

	appelant := action.Appelant{Username: sender_Username, GroupIDs: sender_groupsIDs}

	switch args[0] {
	case "purge-delay":
		return purgeDelay(args[1:], appelant)

	case "metrics-retention":
		return retentionMetriques(args[1:], appelant)

	case "list":
		p := action.Params{}
		if len(args) > 1 {
			p["role"] = strings.ToLower(args[1])
		}
		res, err := action.Executer("cluster.list_nodes", appelant, p)
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		d, ok := res.Donnees.(action.NoeudsCluster)
		if !ok || len(d.Noeuds) == 0 {
			return res.Message
		}
		return display.DisplayClusterNodes(d.Role, d.Noeuds)

	case "expose":
		return exposer(args[1:], appelant)

	case "priority":
		return priorite(args[1:], appelant)

	case "rotation":
		return rotation(args[1:], appelant)

	case "affinity":
		return affinite(args[1:], appelant)

	default:
		return "Commande cluster invalide. Utilisez « cluster -h »."
	}
}

// exposer déclare par où les agents joignent un nœud.
//
//	cluster expose <noeud> <adresse> [port]
//	cluster expose <noeud> --clear
//
// # Pourquoi cette commande existe
//
// Un nœud déclare l'adresse qu'il voit de LUI-MÊME. Derrière une redirection
// NAT, dans un conteneur, ou sur un hôte à plusieurs interfaces, ce n'est pas
// celle par laquelle le parc l'atteint — et il n'a aucun moyen de le savoir.
// Cette adresse privée était pourtant distribuée à toutes les machines.
//
// # Le port est facultatif, et son absence ne l'efface pas
//
// `cluster expose proxy1 203.0.113.5` change l'adresse et laisse le port tel
// quel. L'effacer serait le piège classique d'une mise à jour qui écrit les
// champs qu'on n'a pas nommés : la commande la plus naturelle — corriger
// l'adresse — casserait le port réglé la semaine précédente.
//
// `--clear` retire les DEUX, et c'est le seul geste qui les efface.
func exposer(args []string, appelant action.Appelant) string {
	if len(args) == 0 {
		return usageExpose("nom du nœud manquant")
	}
	p := action.Params{"node": strings.TrimSpace(args[0])}

	switch {
	case len(args) == 1:
		return usageExpose("adresse manquante — utilisez --clear pour retirer la déclaration")

	case strings.TrimSpace(args[1]) == "--clear":
		// Présents et vides : c'est ce qui distingue « efface » de « n'y touche
		// pas ». Voir Params.Presente.
		p["address"] = ""
		p["port"] = ""

	default:
		p["address"] = strings.TrimSpace(args[1])
		if len(args) > 2 {
			p["port"] = strings.TrimSpace(args[2])
		}
		if len(args) > 3 {
			return usageExpose("arguments en trop : " + strings.Join(args[3:], " "))
		}
	}

	res, err := action.Executer("cluster.set_node_exposure", appelant, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

func usageExpose(motif string) string {
	return "Erreur : " + motif + "\n\n" +
		"Usage : vlt cluster expose <noeud> <adresse> [port]\n" +
		"        vlt cluster expose <noeud> --clear\n\n" +
		"  <adresse>  IP ou nom DNS par lequel les AGENTS joignent ce nœud\n" +
		"  [port]     port public, si une redirection le translate ; omis, le port ne change pas\n" +
		"  --clear    retire la déclaration : on retombe sur ce que le nœud voit de lui-même\n\n" +
		"Exemple : vlt cluster expose proxy-paris 203.0.113.5 16666"
}

// priorite règle l'ordre dans lequel un nœud est servi aux agents.
//
// Plus petit = servi plus tôt. Zéro vaut « sans préférence » et se range APRÈS
// les valeurs explicites — sinon donner une priorité à un seul nœud le
// reléguerait derrière tous les autres, l'exact inverse de l'intention.
func priorite(args []string, appelant action.Appelant) string {
	if len(args) < 2 {
		return "Usage : vlt cluster priority <noeud> <valeur>\n\n" +
			"  Plus petit = servi plus tôt. 0 vaut « sans préférence » et se range\n" +
			"  APRÈS les valeurs explicites."
	}

	res, err := action.Executer("cluster.set_node_exposure", appelant, action.Params{
		"node":     strings.TrimSpace(args[0]),
		"priority": strings.TrimSpace(args[1]),
	})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// rotation retire un nœud de la liste servie aux agents, ou l'y remet.
//
// Ce n'est PAS un contrôle d'accès : le drapeau retire une adresse d'une liste,
// il n'empêche personne de se connecter. Le pare-feu reste ce qui protège un
// core. Il sert à sortir un nœud pour maintenance sans le désenregistrer, ce qui
// le ferait disparaître des vues de supervision au moment où on le surveille.
func rotation(args []string, appelant action.Appelant) string {
	if len(args) < 2 {
		return "Usage : vlt cluster rotation <noeud> <in|out>\n\n" +
			"  in   le nœud est annoncé aux agents\n" +
			"  out  il en est retiré, sans être désenregistré du cluster\n\n" +
			"Ce n'est pas un contrôle d'accès : le nœud reste joignable pour qui\n" +
			"connaît son adresse. C'est le pare-feu qui protège un core."
	}

	var expose string
	switch strings.ToLower(strings.TrimSpace(args[1])) {
	case "in":
		expose = "true"
	case "out":
		expose = "false"
	default:
		return "Valeur invalide : attendu « in » ou « out »."
	}

	res, err := action.Executer("cluster.set_node_exposure", appelant, action.Params{
		"node":    strings.TrimSpace(args[0]),
		"exposed": expose,
	})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// purgeDelay lit ou règle le délai avant suppression d'un service parti.
//
// Deux actions distinctes et non un paramètre optionnel : la lecture se
// contente de `read:cluster`, l'écriture exige `write:cluster`. Les confondre
// donnerait à qui consulte le droit de modifier — allonger le délai laisse
// traîner des identités, le raccourcir en détruit plus vite.
func purgeDelay(args []string, appelant action.Appelant) string {
	nom := "cluster.get_purge_delay"
	p := action.Params{}
	if len(args) > 0 {
		nom = "cluster.set_purge_delay"
		p["hours"] = strings.TrimSpace(args[0])
	}

	res, err := action.Executer(nom, appelant, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// retentionMetriques lit ou règle la conservation des métriques de nœuds.
//
// Même découpage en deux actions que purgeDelay, et pour la même raison :
// raccourcir la rétention DÉTRUIT des lignes au prochain balayage. Consulter ne
// doit pas donner ce droit.
func retentionMetriques(args []string, appelant action.Appelant) string {
	nom := "cluster.get_metrics_retention"
	p := action.Params{}
	if len(args) > 0 {
		nom = "cluster.set_metrics_retention"
		p["days"] = strings.TrimSpace(args[0])
	}

	res, err := action.Executer(nom, appelant, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// affinite fixe les groupes qu'un nœud sert en priorité.
//
//	cluster affinity <noeud> <groupe> [groupe...]
//	cluster affinity <noeud> --none
//
// # Ce que l'affinité fait
//
// Un agent membre d'un de ces groupes reçoit ce nœud AVANT les autres de même
// rôle. Préférence et non exclusivité : tous les nœuds exposés restent dans sa
// liste, en queue — sans quoi la panne du proxy d'un site deviendrait une panne
// d'authentification pour ce site.
//
// # Remplacement, jamais ajout
//
// Les groupes donnés deviennent la liste complète. Une commande qui ajouterait
// obligerait à en écrire une seconde pour retirer, et à lire l'état courant pour
// savoir laquelle employer.
func affinite(args []string, appelant action.Appelant) string {
	if len(args) < 2 {
		return "Usage : vlt cluster affinity <noeud> <groupe> [groupe...]\n" +
			"        vlt cluster affinity <noeud> --none\n\n" +
			"  Les agents de ces groupes reçoivent ce nœud en tête de leur liste.\n" +
			"  Les groupes donnés REMPLACENT les précédents ; --none les retire tous.\n\n" +
			"  Ce n'est pas une exclusivité : les autres nœuds restent joignables,\n" +
			"  en queue de liste. C'est ce qui fait qu'un site dont le proxy est\n" +
			"  tombé se rabat sur un core au lieu de n'avoir plus personne."
	}

	groupes := ""
	if strings.TrimSpace(args[1]) != "--none" {
		groupes = strings.Join(args[1:], ",")
	}

	// « groups » est posé même vide : présent vaut décision, absent vaudrait
	// « n'y touche pas », et --none n'aurait alors aucun effet.
	res, err := action.Executer("cluster.set_node_groups", appelant, action.Params{
		"node":   strings.TrimSpace(args[0]),
		"groups": groupes,
	})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

func aide() string {
	return fmt.Sprintf(`cluster — supervision du cluster.

  cluster list                       tous les nœuds enregistrés
  cluster list <role>                nœuds actifs d'un rôle
  cluster purge-delay                délai avant suppression d'un service parti
  cluster purge-delay <heures>       règle ce délai (0 désactive la purge)
  cluster metrics-retention          conservation des métriques de nœuds
  cluster metrics-retention <jours>  la règle (0 conserve sans limite)

  cluster expose <noeud> <adresse> [port]   par où les AGENTS joignent ce nœud
  cluster expose <noeud> --clear            retire la déclaration
  cluster priority <noeud> <valeur>         ordre de service (petit = tôt, 0 = sans préférence)
  cluster rotation <noeud> <in|out>         annoncer ce nœud aux agents, ou l'en retirer
  cluster affinity <noeud> <groupe...>      groupes que ce nœud sert en priorité
  cluster affinity <noeud> --none           retire toute affinité

L'affinité range un nœud devant les autres de son rôle pour les agents des
groupes visés. PRÉFÉRENCE et non exclusivité : les autres nœuds restent dans la
liste, en queue. C'est ce qui fait qu'un site dont le proxy est tombé se rabat
sur un core au lieu de n'avoir plus personne à joindre.

Ordre servi : proxies affins, autres proxies, cores affins, autres cores.

Un nœud déclare l'adresse qu'il voit de LUI-MÊME. Derrière une redirection NAT
ou dans un conteneur, ce n'est pas celle par laquelle le parc l'atteint, et il
n'a aucun moyen de le savoir : « expose » est là pour le lui dire. La
déclaration l'emporte alors sur ce que le nœud annonce, et c'est elle que
reçoivent les agents.

« rotation out » n'est PAS un contrôle d'accès : le nœud disparaît de la liste
distribuée, il reste joignable pour qui connaît son adresse. C'est le pare-feu
qui protège un core.

Un service qui cesse de battre est marqué hors ligne immédiatement. Ce n'est
qu'après le délai ci-dessus que son client est SUPPRIMÉ, et il devra alors se
réenrôler avec une nouvelle clé.

Les métriques au-delà de la rétention sont SUPPRIMÉES, pas résumées : cette
table n'agrège pas. Raccourcir la valeur détruit au prochain balayage.

Droits : %s pour consulter, %s pour régler.`,
		"read:cluster", "write:cluster")
}
