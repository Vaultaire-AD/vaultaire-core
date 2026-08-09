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
		// create -p <nom> <yes/not>
		//
		// Le second argument vaut « permission d'administration web ». Il est
		// transmis tel quel : l'action accepte oui/non/yes/no/1/0, ce qui
		// couvre la forme historique de cette commande comme celle de la case à
		// cocher du formulaire.
		p := commandaction.ParamsDepuisPositionnels(command_list[1:], "name", "web_admin")
		return commandaction.ExecuterAction("permission.create", p, sender_groupsIDs, sender_Username)

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

func aide() string {
	return `create — crée des utilisateurs, groupes, machines, permissions et GPO.

  create -u <identifiant> <domaine> <motdepasse> <jj/mm/aaaa> [prénom] [nom]
  create -g <nom> <domaine>
  create -c <yes/not> [-join <hôte[:port]> <user>]
  create -p <nom> <yes/not>
  create -gpo <nom> --scope <machine|user> [--desc "texte"]

Notes :
  -u  la date de naissance est vérifiée ; prénom et nom sont déduits d'un
      identifiant de la forme « prénom.nom » s'ils ne sont pas fournis.
  -c  crée un agent. Un client service ne se crée pas ici, il s'enrôle seul :
      voir « enroll -h ». Avec -join, l'agent est installé à distance par SSH.
  -p  le second argument accorde ou non l'accès à l'administration web.`
}

// verifierDroit a disparu, et c'était sa raison d'être.
//
// Elle contrôlait les droits des chemins NON portés par une action, et son
// commentaire annonçait : « sa disparition signalera que le portage est
// complet ». Son dernier appelant était « create -gpo », désormais porté par
// l'action gpo.create.
//
// Plus aucune création ne décide des droits hors du registre.
