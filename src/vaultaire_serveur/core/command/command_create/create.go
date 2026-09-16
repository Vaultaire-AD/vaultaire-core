package commandcreate

import (
	"vaultaire/core/action"
	commandaction "vaultaire/core/command/commandaction"
	autoaddclientgo "vaultaire/ducky-network/new_client/AUTO_ADD_client.go"
)

// Commande « create ».
//
// # Ce que cette commande ne fait plus
//
// Elle ne vérifie plus les droits et n'écrit plus en base. Son rôle se réduit à
// ce qu'elle est seule à savoir faire : comprendre la syntaxe
// « create -u alice paris.fr motdepasse 01/01/1990 » et la traduire en
// paramètres nommés.
//
// Le contrôle et l'effet vivent dans core/action, partagés avec l'interface
// web. C'est ce qui empêche les deux de diverger — ce qu'elles avaient fait sur
// la création d'utilisateur, où cette commande acceptait une date de naissance
// invalide que le web refusait.
//
// # Ce qui change pour l'utilisateur
//
// Trois refus nouveaux, tous des corrections :
//
//   - une date de naissance mal formée est refusée, au lieu d'être écrite telle
//     quelle en base ;
//   - un mot de passe vide est refusé, au lieu de créer un compte dont le haché
//     est celui de la chaîne vide ;
//   - « create -g monGroupe » sans domaine rend une erreur au lieu de faire
//     paniquer le serveur sur un dépassement d'indice.

// ActionsUtilisees liste les actions du registre que cette commande appelle.
//
// Vérifiée au démarrage : une action absente échouerait sinon au moment où
// quelqu'un tape la commande.
var ActionsUtilisees = []string{
	"user.create",
	"group.create",
	"client.create",
	"permission.create",
	"client_permission.create",
}

// Create_Command traite « create … ».
//
// La signature est inchangée : les droits sont toujours reçus, mais transmis au
// registre au lieu d'être vérifiés ici.
func Create_Command(command_list []string, sender_groupsIDs []int, sender_Username string) string {
	if len(command_list) == 0 {
		return aide()
	}

	switch command_list[0] {
	case "-h", "help", "--help":
		return aide()

	case "-u":
		// create -u <identifiant> <domaine> <motdepasse> <naissance> [prénom] [nom]
		//
		// Les noms correspondent à ceux qu'attend l'action, qui sont aussi ceux
		// des champs du formulaire web. C'est ce qui fait que les deux façades
		// aboutissent au même appel.
		p := commandaction.ParamsDepuisPositionnels(command_list[1:],
			"username", "domain", "password", "birthdate", "firstname", "lastname")
		return commandaction.ExecuterAction("user.create", p, sender_groupsIDs, sender_Username)

	case "-g":
		// create -g <nom> <domaine>
		//
		// L'ancienne version lisait command_list[2] après avoir vérifié
		// seulement `len < 2` : « create -g monGroupe » sortait du tableau et
		// faisait paniquer la goroutine, donc s'arrêter le processus.
		p := commandaction.ParamsDepuisPositionnels(command_list[1:], "group", "domain")
		return commandaction.ExecuterAction("group.create", p, sender_groupsIDs, sender_Username)

	case "-c":
		return create_ClientSoftware(command_list, sender_groupsIDs, sender_Username)

	case "-p":
		// create -p <nom> <oui/non> [--desc "texte"]
		//
		// Le second argument vaut « permission d'administration web ». Il est
		// transmis tel quel : l'action accepte oui/non/yes/no/1/0, ce qui
		// couvre la forme historique de cette commande comme celle de la case à
		// cocher du formulaire.
		//
		// LA DESCRIPTION N'ÉTAIT PAS TRANSMISE. L'action la lit — `description`
		// —, la base porte la colonne, la fiche l'affiche, et le formulaire web
		// la renseigne : seule cette commande n'avait aucun moyen de la fournir.
		// Une permission créée en ligne de commande naissait donc anonyme, et
		// rien n'a jamais permis de la décrire ensuite.
		options, positionnels := extraireOptions(command_list[1:])
		p := commandaction.ParamsDepuisPositionnels(positionnels, "name", "web_admin")
		p = commandaction.FusionnerParams(p, options)
		return commandaction.ExecuterAction("permission.create", p, sender_groupsIDs, sender_Username)

	case "-pc":
		// create -pc <nom> <oui/non>
		//
		// Les permissions CLIENT ne se créaient nulle part en ligne de commande.
		// L'action client_permission.create existait, l'interface web l'appelait,
		// `get -p -c` savait afficher le résultat — mais aucune commande ne
		// permettait d'en créer une. Le seul chemin était le portail web.
		//
		// Le second argument accorde l'administration aux MACHINES du groupe qui
		// portera la permission ; il est nommé `is_admin` et non `web_admin`,
		// parce qu'il ne s'agit pas du même privilège.
		p := commandaction.ParamsDepuisPositionnels(command_list[1:], "name", "is_admin")
		return commandaction.ExecuterAction("client_permission.create", p, sender_groupsIDs, sender_Username)

	case "-gpo":
		// Le contrôle de droits qui vivait ici a disparu : l'action gpo.create
		// le porte. Le garder en plus aurait fait deux endroits où le droit se
		// décide pour un seul geste — donc deux endroits à tenir d'accord.
		return create_GPO(command_list, sender_groupsIDs, sender_Username)

	default:
		return "Requête invalide. Essayez « create -h »."
	}
}

// create_ClientSoftware crée un agent, puis l'installe si « -join » est fourni.
//
// Deux temps distincts, et c'est pourquoi cette commande ne se réduit pas à un
// appel d'action : la création passe par le registre, l'installation à distance
// est une opération réseau qui n'a pas sa place dans une action métier.
//
//	create -c <yes/not> [-join <hôte[:port]> <user>]
//
// Le port est facultatif et vaut 22. « -join 192.168.30.8:2222 root » vise une
// machine dont sshd écoute ailleurs ; une adresse IPv6 suivie d'un port s'écrit
// entre crochets.
//
// Le TYPE n'est pas demandé : ce chemin ne crée qu'un client basic. Un client
// service s'enrôle lui-même avec sa propre paire de clés — sa clé privée ne doit
// jamais quitter l'hôte qui l'utilisera.
func create_ClientSoftware(command_list []string, groupIDs []int, sender string) string {
	if len(command_list) < 2 {
		return "Requête invalide : create -c <yes/not> [-join <hôte[:port]> <user>]"
	}

	p := commandaction.ParamsDepuisPositionnels(command_list[1:], "is_serveur")
	res, err := action.Executer("client.create",
		action.Appelant{Username: sender, GroupIDs: groupIDs}, p)
	if err != nil {
		return commandaction.MessageDErreur(err)
	}

	// L'identifiant est lu dans les données et non extrait du message : le
	// message est destiné à un humain et peut être reformulé, les données non.
	computeurID := ""
	if d, ok := res.Donnees.(map[string]string); ok {
		computeurID = d["computeur_id"]
	}
	if computeurID == "" {
		// La machine est créée ; seul son identifiant est illisible. Le dire
		// plutôt que de laisser croire à un échec, qui ferait recommencer et
		// créerait une seconde identité inutile.
		return res.Message + " (identifiant illisible dans le résultat)"
	}

	if len(command_list) >= 4 && command_list[2] == "-join" {
		return autoaddclientgo.Manage_Auto_ADD_client(command_list[4], command_list[3], computeurID)
	}
	return res.Message
}

// extraireOptions sépare les options longues des arguments positionnels.
//
// `SplitArgsPreserveBlocks`, en amont, a déjà regroupé ce qui suit une option
// longue en un seul argument : « --desc lecture seule » arrive comme
// « --desc », « lecture seule ». On n'a donc pas à gérer les guillemets ici.
//
// Les options sont retirées de la liste rendue : sans cela, « create -p lecture
// oui --desc "…" » verrait `--desc` compté comme un positionnel, et l'action
// recevrait un nom ou un booléen aberrant selon la position.
func extraireOptions(args []string) (action.Params, []string) {
	options := action.Params{}
	positionnels := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--desc", "-d":
			if i+1 < len(args) {
				options["description"] = args[i+1]
				i++
			}
		default:
			positionnels = append(positionnels, args[i])
		}
	}
	return options, positionnels
}

func aide() string {
	// « yes/not » a disparu de cette aide, et ce n'était pas un détail de
	// rédaction : « not » n'a JAMAIS été accepté. Les valeurs reconnues sont
	// oui/non, yes/no, true/false, on/off, 1/0. Qui recopiait l'aide à la lettre
	// obtenait « valeur "not" invalide : attendu oui/non » et n'avait aucune
	// raison de soupçonner l'aide elle-même.
	return `create — crée des utilisateurs, groupes, machines, permissions et GPO.

  create -u <identifiant> <domaine> <motdepasse> <jj/mm/aaaa> [prénom] [nom]
  create -g <nom> <domaine>
  create -c <oui|non> [-join <hôte[:port]> <user>]
  create -p <nom> <oui|non> [--desc "texte"]
  create -pc <nom> <oui|non>
  create -gpo <nom> --scope <machine|user> [--desc "texte"]

Notes :
  -u   la date de naissance est vérifiée ; prénom et nom sont déduits d'un
       identifiant de la forme « prénom.nom » s'ils ne sont pas fournis.
  -c   crée un agent. Un client service ne se crée pas ici, il s'enrôle seul :
       voir « enroll -h ». Avec -join, l'agent est installé à distance par SSH.
  -p   permission UTILISATEUR. Le second argument accorde ou non l'accès à
       l'administration web. La permission naît sans aucun droit RBAC : les
       régler ensuite avec « update -pu », les consulter avec « get -p -u ».
  -pc  permission CLIENT. Le second argument accorde ou non l'administration
       aux MACHINES du groupe qui la portera — ce n'est pas le même privilège
       que -p.

Les valeurs booléennes acceptées sont oui|non, yes|no, true|false, on|off, 1|0.`
}

// verifierDroit a disparu, et c'était sa raison d'être.
//
// Elle contrôlait les droits des chemins NON portés par une action, et son
// commentaire annonçait : « sa disparition signalera que le portage est
// complet ». Son dernier appelant était « create -gpo », désormais porté par
// l'action gpo.create.
//
// Plus aucune création ne décide des droits hors du registre.
