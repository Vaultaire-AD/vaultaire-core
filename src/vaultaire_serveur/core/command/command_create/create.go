package commandcreate

import (
	"os"
	"strconv"

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
	"client.export",
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

	case "-export":
		// create -export <computeur_id> <fichier> [--os <linux|windows>]
		//
		// Sous « create » et non sous une commande à soi : c'est la même chose
		// que « create -c --export », pour une machine née plus tôt. En faire
		// une commande séparée aurait éloigné deux gestes qu'on apprend
		// ensemble.
		return exporter_ClientSoftware(command_list, sender_groupsIDs, sender_Username)

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

	options, positionnels, errOpt := extraireOptionsClient(command_list[1:])
	if errOpt != "" {
		return errOpt
	}

	// `-join` et `--export` se CONTREDISENT, et il faut le dire.
	//
	// `-join` installe la machine à distance et lui dépose son identité par SSH ;
	// `--export` produit la même identité dans un fichier à emporter. Demander
	// les deux, c'est ne pas savoir laquelle des deux voies on emprunte. Une
	// première version les acceptait toutes les deux et en exécutait une seule,
	// laquelle dépendant de l'ORDRE des arguments — donc en abandonnant l'autre
	// sans un mot.
	joinDemande := len(positionnels) >= 2 && positionnels[1] == "-join"
	if joinDemande && options["export"] != "" {
		return "« -join » et « --export » ne vont pas ensemble : -join installe la machine à " +
			"distance et lui dépose son identité, --export la met dans un fichier à emporter. " +
			"Choisissez la voie."
	}

	p := commandaction.ParamsDepuisPositionnels(positionnels, "is_serveur")
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

	if joinDemande {
		// Sur les POSITIONNELS, et avec la bonne borne.
		//
		// La version précédente lisait command_list[4] après avoir vérifié
		// « len >= 4 » : « create -c non -join hote », qui fait exactement quatre
		// éléments, faisait PANIQUER le serveur. C'est le défaut que l'en-tête
		// de ce fichier se félicite d'avoir corrigé sur « create -g », resté ici.
		if len(positionnels) < 4 {
			return "Requête invalide : create -c <oui|non> -join <hôte[:port]> <user>\n" +
				"La machine " + computeurID + " a bien été créée : reprenez avec « -join » seul."
		}
		return autoaddclientgo.Manage_Auto_ADD_client(positionnels[3], positionnels[2], computeurID)
	}

	// L'export est tenté APRÈS la création, et son échec ne la défait pas : la
	// machine existe, son identité est sur le core. Rendre une erreur sèche
	// ferait recommencer, donc créerait une seconde identité pour rien.
	if chemin := options["export"]; chemin != "" {
		return res.Message + "\n" + ecrireArchive(sender, groupIDs, computeurID, options["systeme"], chemin)
	}
	return res.Message
}

// exporter_ClientSoftware compose l'archive d'une machine déjà créée.
//
//	create -export <computeur_id> <fichier> [--os <linux|windows>]
func exporter_ClientSoftware(command_list []string, groupIDs []int, sender string) string {
	options, positionnels, errOpt := extraireOptionsClient(command_list[1:])
	if errOpt != "" {
		return errOpt
	}
	if len(positionnels) < 2 {
		return "Requête invalide : create -export <computeur_id> <fichier> [--os <linux|windows>]"
	}
	return ecrireArchive(sender, groupIDs, positionnels[0], options["systeme"], positionnels[1])
}

// ecrireArchive demande l'archive au registre et la pose sur le disque.
func ecrireArchive(sender string, groupIDs []int, computeurID, systeme, chemin string) string {
	res, err := action.Executer("client.export",
		action.Appelant{Username: sender, GroupIDs: groupIDs},
		action.Params{"computeur_id": computeurID, "systeme": systeme})
	if err != nil {
		return "archive non composée : " + commandaction.MessageDErreur(err)
	}

	archive, ok := res.Donnees.(action.ArchiveClient)
	if !ok {
		return "archive illisible dans le résultat"
	}

	// 0600, et le dire — mais pas par le seul WriteFile.
	//
	// Le fichier porte une clé privée de machine. Le laisser en 0644 dans un
	// répertoire partagé reviendrait à publier l'identité du poste à tout compte
	// du core — précisément ce que l'archive doit éviter, elle qui existe pour
	// remplacer un « docker exec » dans un répertoire en 0700.
	//
	// Le Chmod n'est PAS redondant : le mode d'os.WriteFile ne s'applique qu'à la
	// CRÉATION. Réexporter vers un chemin déjà là — un second essai, un fichier
	// préparé à l'avance — laissait le mode existant tandis que le message
	// affirmait 0600.
	if err := os.WriteFile(chemin, archive.Contenu, 0600); err != nil {
		return "archive non écrite dans " + chemin + " : " + err.Error()
	}
	if err := os.Chmod(chemin, 0600); err != nil {
		return "archive écrite dans " + chemin + " mais ses droits n'ont pas pu être restreints : " +
			err.Error() + "\nElle contient une CLÉ PRIVÉE : corrigez-les à la main (chmod 600)."
	}
	return "Archive écrite : " + chemin + " (" + archive.Systeme + ", " +
		strconv.Itoa(len(archive.Contenu)) + " octets, mode 0600).\n" +
		"Elle contient la CLÉ PRIVÉE de la machine : effacez-la une fois l'agent installé."
}

// extraireOptionsClient sépare « --export » et « --os » des positionnels.
//
// Le même motif qu'extraireOptions, et pas la même fonction : celle-là ne
// connaît que « --desc », et lui ajouter des options d'un autre sujet en ferait
// un fourre-tout où une faute de frappe sur « --desc » deviendrait un chemin
// d'export silencieux.
// Une option sans valeur est REFUSÉE, avec un message.
//
// Les avaler en silence — ce que fait extraireOptions pour « --desc » — rendait
// « create -c non --export » identique à « create -c non » : la machine était
// créée, aucune archive n'était écrite, et rien ne le disait. Sur une option
// dont tout l'intérêt est le fichier produit, c'est le pire des deux mondes.
func extraireOptionsClient(args []string) (map[string]string, []string, string) {
	options := map[string]string{}
	positionnels := make([]string, 0, len(args))

	for i := 0; i < len(args); i++ {
		var cle string
		switch args[i] {
		case "--export":
			cle = "export"
		case "--os":
			cle = "systeme"
		default:
			positionnels = append(positionnels, args[i])
			continue
		}
		if i+1 >= len(args) {
			return nil, nil, "l'option « " + args[i] + " » attend une valeur"
		}
		options[cle] = args[i+1]
		i++
	}
	return options, positionnels, ""
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
  create -c <oui|non> [-join <hôte[:port]> <user>] [--os <linux|windows>] [--export <fichier>]
  create -export <computeur_id> <fichier> [--os <linux|windows>]
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
