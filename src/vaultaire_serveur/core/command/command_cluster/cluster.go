package commandcluster

import (
	"fmt"
	"strings"

	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/command/display"
	hosthandler "vaultaire/ducky-network/host_handler"
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
//	cluster relais <proxy>               ce qu'un proxy expose, et son état
//	cluster relais <proxy> set <nom> …   ajoute ou modifie un relais
//	cluster relais <proxy> remove <nom>  retire un relais
//	cluster relais <proxy> release       rend la main au fichier du proxy
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

	case "refresh":
		return actualiserListes(args[1:], appelant)

	case "relais", "relay":
		return relais(args[1:], appelant)

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

// purgeDelay lit ou règle le délai avant suppression d'un service ou d'un nœud parti.
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

// actualiserListes traite `cluster refresh <machine> | --all | -g <groupe>`.
//
// # Pourquoi une cible obligatoire
//
// Une actualisation peut provoquer une RECONNEXION : si le nœud utilisé n'est
// plus le mieux placé, l'agent ferme son tunnel et repart sur le premier de la
// liste. Le demander à tout le parc est une opération légitime — après une
// bascule de cluster — mais ce n'est pas ce qu'on veut quand on a simplement
// oublié de taper un identifiant.
//
// # Pourquoi la boucle est ici et pas dans l'action
//
// Chaque machine est contrôlée pour elle-même : un administrateur délégué
// actualise les siennes et se voit refuser les autres, au lieu de tout ou rien.
// Le décompte final le dit.
func actualiserListes(args []string, appelant action.Appelant) string {
	cible := ""
	if len(args) > 0 {
		cible = strings.TrimSpace(args[0])
	}

	switch cible {
	case "":
		return "Usage : vlt cluster refresh <computeur_id> | --all | -g <groupe>\n\n" +
			"La machine redemande la liste des nœuds joignables, au lieu d'attendre son\n" +
			"prochain tour. Si le nœud qu'elle utilise n'est plus le mieux placé, elle\n" +
			"rouvre son tunnel sur celui qui l'est. Une machine hors ligne le fera à sa\n" +
			"reconnexion."

	case "--all", "-a":
		return actualiserPlusieurs(appelant, hosthandler.MachinesEnLigne(),
			"aucune machine connectée : il n'y a personne à qui demander une actualisation.")

	case "-g", "--group":
		if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
			return "Usage : vlt cluster refresh -g <groupe>"
		}
		groupe := strings.TrimSpace(args[1])
		res, err := action.Executer("group.list_clients", appelant, action.Params{"group": groupe})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		d, ok := res.Donnees.(action.MachinesDeGroupe)
		if !ok {
			return res.Message
		}
		var ids []string
		for _, m := range d.Machines {
			ids = append(ids, m.ComputeurID)
		}
		return actualiserPlusieurs(appelant, ids,
			"aucune machine dans le groupe "+groupe+".")
	}

	res, err := action.Executer("cluster.refresh_nodes", appelant,
		action.Params{"computeur_id": cible})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// actualiserPlusieurs pousse la demande à une liste de machines.
func actualiserPlusieurs(appelant action.Appelant, machines []string, siVide string) string {
	if len(machines) == 0 {
		return siVide
	}

	jointes, refusees, horsLigne := 0, 0, 0
	for _, id := range machines {
		res, err := action.Executer("cluster.refresh_nodes", appelant,
			action.Params{"computeur_id": id})
		if err != nil {
			// Hors périmètre, ou machine inconnue de l'annuaire : compté, pas
			// détaillé. Lister les machines qu'on n'a pas le droit de toucher
			// renseignerait sur un parc qu'on n'a pas le droit de voir.
			refusees++
			continue
		}
		if remis, _ := res.Donnees.(bool); remis {
			jointes++
		} else {
			horsLigne++
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "Actualisation demandée à %d machine(s) sur %d.\n", jointes, len(machines))
	if horsLigne > 0 {
		fmt.Fprintf(&b, "%d hors ligne : elles reliront leur liste à leur reconnexion.\n", horsLigne)
	}
	if refusees > 0 {
		fmt.Fprintf(&b, "%d machine(s) hors de votre périmètre n'ont pas été touchées.\n", refusees)
	}
	return b.String()
}

func aide() string {
	return fmt.Sprintf(`cluster — supervision du cluster.

  cluster list                       tous les nœuds enregistrés
  cluster list <role>                nœuds actifs d'un rôle
  cluster purge-delay                délai avant suppression d'un service ou d'un nœud parti
  cluster purge-delay <heures>       règle ce délai (0 désactive la purge)
  cluster metrics-retention          conservation des métriques de nœuds
  cluster metrics-retention <jours>  la règle (0 conserve sans limite)

  cluster expose <noeud> <adresse> [port]   par où les AGENTS joignent ce nœud
  cluster expose <noeud> --clear            retire la déclaration
  cluster priority <noeud> <valeur>         ordre de service (petit = tôt, 0 = sans préférence)
  cluster rotation <noeud> <in|out>         annoncer ce nœud aux agents, ou l'en retirer
  cluster affinity <noeud> <groupe...>      groupes que ce nœud sert en priorité
  cluster affinity <noeud> --none           retire toute affinité

  cluster refresh <computeur_id>            la machine redemande la liste des nœuds
  cluster refresh --all                     toutes les machines connectées
  cluster refresh -g <groupe>               les machines d'un groupe

  cluster relais <proxy>                    ce que ce proxy expose, vers quoi, et son état
  cluster relais <proxy> set <nom> [options]   ajoute ou modifie un relais (voir « cluster relais -h »)
  cluster relais <proxy> remove <nom>       retire un relais
  cluster relais <proxy> release            rend la main au fichier de configuration du proxy

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

Droits : %s pour consulter, %s pour régler, %s pour décider ce qu'un proxy expose.`,
		"read:cluster", "write:cluster", "write:relay")
}

// relais traite `cluster relais …` (TO-DO 141).
//
//	cluster relais <proxy>
//	cluster relais <proxy> set <nom> [--type T] [--ecoute [adr]:port] [--source S]
//	                                 [--adresses a:p,b:p] [--port-cible N]
//	                                 [--delai s] [--inactivite s] [--max N] [--max-par-source N]
//	cluster relais <proxy> remove <nom>
//	cluster relais <proxy> release
//
// # Les options de « set » ne touchent que ce qu'elles nomment
//
// Sur un relais qui existe, une option absente laisse le champ tel quel. C'est
// le parti de « cluster expose » : la commande la plus naturelle — changer un
// plafond — ne doit pas remettre le port à son défaut.
func relais(args []string, appelant action.Appelant) string {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		return aideRelais("")
	}
	noeud := strings.TrimSpace(args[0])

	if len(args) == 1 {
		res, err := action.Executer("cluster.relay_list", appelant, action.Params{"node": noeud})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		d, ok := res.Donnees.(action.RelaisDuNoeud)
		if !ok {
			return res.Message
		}
		return display.DisplayRelais(d.Noeud, d.EnLigne, d.Vue)
	}

	switch strings.ToLower(args[1]) {
	case "set", "add":
		if len(args) < 3 || strings.HasPrefix(args[2], "-") {
			return aideRelais("nom du relais manquant")
		}
		p := action.Params{"node": noeud, "name": strings.TrimSpace(args[2])}
		if motif := lireOptionsDeRelais(args[3:], p); motif != "" {
			return aideRelais(motif)
		}
		res, err := action.Executer("cluster.relay_set", appelant, p)
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		return res.Message

	case "remove", "rm", "delete":
		if len(args) != 3 {
			return aideRelais("« remove » attend le nom d'un relais, et rien d'autre")
		}
		res, err := action.Executer("cluster.relay_remove", appelant,
			action.Params{"node": noeud, "name": strings.TrimSpace(args[2])})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		return res.Message

	case "release":
		if len(args) != 2 {
			return aideRelais("« release » ne prend pas d'argument")
		}
		res, err := action.Executer("cluster.relay_release", appelant, action.Params{"node": noeud})
		if err != nil {
			return commandaction.MessageDErreur(err)
		}
		return res.Message

	default:
		return aideRelais("sous-commande « " + args[1] + " » inconnue")
	}
}

// optionsDeRelais associe chaque option à son paramètre d'action.
//
// Les noms suivent les clés du fichier YAML du proxy : qui a déjà écrit un
// relais dans ce fichier retrouve les mêmes mots ici.
var optionsDeRelais = map[string]string{
	"--type":           "type",
	"--ecoute":         "listen",
	"--listen":         "listen",
	"--source":         "source",
	"--adresses":       "addresses",
	"--cibles":         "addresses",
	"--port-cible":     "target_port",
	"--delai":          "connect_timeout",
	"--inactivite":     "idle",
	"--max":            "max_connections",
	"--max-par-source": "max_per_source",
}

// lireOptionsDeRelais range les options dans p. Rend un motif de refus, ou "".
func lireOptionsDeRelais(args []string, p action.Params) string {
	for i := 0; i < len(args); i++ {
		option, valeur, colle := strings.Cut(args[i], "=")
		parametre, connue := optionsDeRelais[option]
		if !connue {
			return "option « " + option + " » inconnue"
		}
		if !colle {
			if i+1 >= len(args) {
				return "valeur manquante après " + option
			}
			i++
			valeur = args[i]
		}
		if _, deja := p[parametre]; deja {
			return "option " + option + " donnée deux fois"
		}
		p[parametre] = strings.TrimSpace(valeur)
	}
	return ""
}

func aideRelais(motif string) string {
	entete := ""
	if motif != "" {
		entete = "Erreur : " + motif + ".\n\n"
	}
	return entete + `cluster relais — ce qu'un proxy expose, et vers quoi.

  cluster relais <proxy>                    configuration, cibles, état et compteurs
  cluster relais <proxy> set <nom> [options]   ajoute un relais, ou modifie celui de ce nom
  cluster relais <proxy> remove <nom>       retire un relais (jamais le relais Ducky)
  cluster relais <proxy> release            rend la main au fichier de configuration du proxy

Options de « set » — sur un relais qui existe, celles qu'on ne donne pas ne changent pas :

  --type <ducky|https|ldaps>     ce qui est relayé ; « ldap » en clair est refusé
  --ecoute <[adresse]:port>      où le proxy écoute ; défaut 443 (https), 636 (ldaps)
  --source <cores|liste|service:<type>>
                                 d'où viennent les cibles :
                                   cores           les cores du cluster (ducky, ldaps)
                                   service:<type>  les services de ce type, ex. service:vaultaire_nexus (https)
                                   liste           les adresses données par --adresses
  --adresses <hôte:port,…>       cibles d'une source « liste »
  --port-cible <n>               port à joindre sur les cores (source « cores » ; 636 par défaut en ldaps)
  --delai <s>                    délai pour joindre une cible          (0 : le défaut du proxy)
  --inactivite <s>               silence au-delà duquel une connexion est fermée
  --max <n>                      connexions simultanées, au total
  --max-par-source <n>           connexions simultanées par adresse cliente

Exemples :

  cluster relais proxy1 set nexus --type https --ecoute :8843 --source service:vaultaire_nexus
  cluster relais proxy1 set ldaps --type ldaps --ecoute :1636
  cluster relais proxy1 set nexus --max 200
  cluster relais proxy1 remove ldaps

Le proxy applique SANS REDÉMARRER : les tunnels en cours ne sont pas coupés. Le
core demande, le proxy dit ce qu'il a obtenu — un port déjà pris ou un port bas
qu'il n'a pas le droit d'ouvrir donne un relais « refusé », avec le motif.

Tant que le core n'a rien décidé pour un proxy, celui-ci applique son fichier.
La première écriture PREND LA MAIN en repartant de ce qui tourne ; « release »
la rend. Un proxy garde sur son disque la dernière liste reçue : redémarré, il
la rouvre telle quelle, sans repasser par son fichier.

Le relais Ducky ne se retire pas et ne change pas de port : c'est le port que
le proxy a annoncé au cluster (-listen-port), et celui que reçoivent les agents.

Droits : read:cluster pour consulter, write:relay pour modifier.`
}
