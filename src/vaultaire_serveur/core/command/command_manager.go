package command

import (
	"fmt"
	"net"
	"strings"
	"vaultaire/core/action"
	commandadd "vaultaire/core/command/command_add"
	commandcertificate "vaultaire/core/command/command_certificate"
	commandcluster "vaultaire/core/command/command_cluster"
	commandcreate "vaultaire/core/command/command_create"
	commanddelete "vaultaire/core/command/command_delete"
	commanddns "vaultaire/core/command/command_dns"
	commandenroll "vaultaire/core/command/command_enroll"
	commandeyes "vaultaire/core/command/command_eyes"
	commandget "vaultaire/core/command/command_get"
	commandgpo "vaultaire/core/command/command_gpo"
	commandkill "vaultaire/core/command/command_kill"
	commandmfa "vaultaire/core/command/command_mfa"
	commandremove "vaultaire/core/command/command_remove"
	commandsettings "vaultaire/core/command/command_settings"
	commandstatus "vaultaire/core/command/command_status"
	commandupdate "vaultaire/core/command/command_update"
	commandaction "vaultaire/core/command/commandaction"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Exécute une commande et retourne le résultat
func ExecuteCommand(input, sender string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return "Erreur : commande vide."
	}

	args := SplitArgsPreserveBlocks(input)
	if len(args) == 0 {
		return "Erreur : commande vide."
	}
	if len(args) == 1 {
		args = append(args, "-h")
	}

	cmd, argv := args[0], args[1:]

	// Routage RBAC : chaque commande détermine elle-même la clé d'action (catégorie:action:objet)
	commandTable := map[string]func([]string, []int, string) string{
		"add":         commandadd.Add_Command,
		"remove":      commandremove.Remove_Command,
		"update":      commandupdate.Update_Command,
		"delete":      commanddelete.Delete_Command,
		"dns":         commanddns.DNS_Command,
		"status":      commandstatus.Status_Command,
		"create":      commandcreate.Create_Command,
		"get":         commandget.Get_Command,
		"eyes":        commandeyes.Eyes_Command,
		"cluster":     commandcluster.Cluster_Command,
		"kill":        commandkill.Kill_Command,
		"mfa":         commandmfa.MFA_Command,
		"enroll":      commandenroll.Enroll_Command,
		"gpo":         commandgpo.GPO_Command,
		"certificate": commandcertificate.Certificate_Command,
		"settings":    commandsettings.Settings_Command,
	}

	if cmd == "clear" {
		return handleClear(sender)
	}
	if cmd == "help" {
		return `Commandes disponibles :
  create [OPTIONS] : crée une nouvelle entrée.
  get    [OPTIONS] : consulte utilisateurs, groupes, permissions, clients, GPO.
  add / remove     : rattache ou détache une entité.
  update [OPTIONS] : modifie une entité existante.
  delete [OPTIONS] : supprime une entité (delete -u supprime aussi les comptes locaux).
  kill   [OPTIONS] : désactivation d'urgence d'un compte. Voir kill -h.
  mfa    [OPTIONS] : second facteur et politique de mot de passe. Voir mfa -h.
  enroll [OPTIONS] : clés d'enrôlement des clients service. Voir enroll -h.
  gpo    [OPTIONS] : état d'application et de conformité des GPO. Voir gpo -h.
  certificate      : certificats TLS du serveur (LDAPS). Voir certificate -h.
  settings         : durées d'exploitation du serveur. Voir settings -h.
  status [OPTIONS] : Vérifie l'état du serveur.
  eyes / cluster   : arborescence de l'annuaire, état du cluster.
  clear            : Nettoie les sessions.
  help             : Affiche cette aide.`
	}

	entry, ok := commandTable[cmd]
	if !ok {
		return fmt.Sprintf("Commande inconnue : %s. Tapez 'help' pour plus d'informations.", cmd)
	}

	groupIDs, err := permission.GetGroupIDsForUser(sender)
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}

	// QUI A TAPÉ QUOI — journalisé ici, une fois, pour les deux façades.
	//
	// # Ce qui manquait
	//
	// Rien ne traçait la commande elle-même. Les ACTIONS journalisent leurs
	// écritures, mais les lectures sont volontairement muettes : exécuter
	// « get -u » ou « eyes -g » depuis la console d'administration web ne
	// laissait donc AUCUNE trace. Ni la commande, ni son auteur.
	//
	// Ce n'est pas anodin pour cette façade en particulier. La console web
	// exécute des commandes `vlt` arbitraires et elle est atteignable par tout
	// détenteur de `web_admin`, à travers le réseau. Le socket local, lui,
	// suppose déjà un accès root à la machine.
	//
	// # Pourquoi la commande est CAVIARDÉE
	//
	// Une commande porte parfois un mot de passe en clair — « create -u alice
	// paris.fr <motdepasse> », « update -u alice -p <motdepasse> ». Journaliser
	// la ligne telle quelle écrirait ces secrets dans un fichier conservé,
	// recopié et souvent lisible par plus de monde que la base. On aurait
	// remplacé une absence de trace par une fuite.
	logs.Write_LogCode("INFO", logs.CodeNone,
		"commande de "+sender+" : "+CommandePourJournal(input))

	return entry(argv, groupIDs, sender)
}

// argumentsSensibles dit, pour une commande donnée, à partir de quel rang les
// arguments portent un secret.
//
// La position est fixée par la GRAMMAIRE de chaque commande, pas devinée : un
// caviardage approximatif masquerait des arguments utiles au diagnostic, ou
// pire, en laisserait passer un.
//
//	create -u <identifiant> <domaine> <MOTDEPASSE> <naissance> …   rang 4
//	update -u <identifiant> -p <MOT DE PASSE…>                     rang 4 et suivants
//
// Les autres commandes ne transportent aucun secret : une clé publique SSH est
// publique, et « enroll create » PRODUIT un secret au lieu d'en recevoir un.
var argumentsSensibles = []struct {
	prefixe []string // les mots qui identifient la commande, rang par rang
	rang    int      // premier argument à caviarder
	etSuite bool     // caviarder aussi tout ce qui suit
}{
	// create -u <identifiant> <domaine> <MOTDEPASSE> <naissance> [prénom] [nom]
	{prefixe: []string{"create", "-u"}, rang: 4, etSuite: false},

	// update -u <identifiant> -p <MOT DE PASSE…>
	//
	// etSuite, parce que le mot de passe occupe TOUS les arguments restants :
	// la commande les rejoint pour qu'un mot de passe contenant des espaces ne
	// soit pas tronqué au premier.
	{prefixe: []string{"update", "-u", "", "-p"}, rang: 4, etSuite: true},
}

// CommandePourJournal rend la commande privée de ses secrets.
//
// Exportée pour être éprouvée : c'est une fonction dont l'échec est SILENCIEUX
// — un mot de passe non caviardé ne se découvre que dans le journal, après coup,
// et le journal est justement ce qu'on recopie et conserve.
func CommandePourJournal(input string) string {
	mots := strings.Fields(input)
	if len(mots) == 0 {
		return ""
	}

	for _, regle := range argumentsSensibles {
		if !correspond(mots, regle.prefixe) || len(mots) <= regle.rang {
			continue
		}
		if regle.etSuite {
			// La queue entière devient UN seul « *** ». Un « *** *** *** » dirait
			// combien de mots comptait le mot de passe — une indication qu'on
			// n'a aucune raison d'écrire, et qui rétrécit la recherche pour qui
			// lira le journal.
			return strings.Join(append(mots[:regle.rang], "***"), " ")
		}
		mots[regle.rang] = "***"
		break
	}
	return strings.Join(mots, " ")
}

// correspond compare les mots au motif, rang par rang.
//
// Une chaîne vide dans le motif signifie « n'importe quoi à ce rang » : c'est
// ainsi que « update -u <identifiant> -p » se décrit sans connaître le nom du
// compte.
//
// Le motif doit être ENTIÈREMENT présent. Une commande plus courte ne
// correspond pas : « update -u alice » sans « -p » n'a pas de mot de passe à
// masquer, et le caviarder quand même priverait le journal de ce qui a
// réellement été tapé de travers.
func correspond(mots, motif []string) bool {
	if len(mots) < len(motif) {
		return false
	}
	for i, attendu := range motif {
		if attendu == "" {
			continue
		}
		if !strings.EqualFold(mots[i], attendu) {
			return false
		}
	}
	return true
}

// handleClear purge les sessions expirées.
//
// # Le droit a changé
//
// La commande exigeait `write:update:user` — le droit de MODIFIER DES COMPTES —
// pour vider une table de sessions. La clé accordait beaucoup plus que ce que
// la commande fait, et son nom ne laissait pas deviner qu'elle ouvrait ce
// réglage.
//
// Elle exige maintenant `write:server`, partagée avec le mode debug.
func handleClear(sender string) string {
	groupIDs, err := permission.GetGroupIDsForUser(sender)
	if err != nil {
		return "Erreur de permission : " + err.Error()
	}
	res, err := action.Executer("server.clear_sessions",
		action.Appelant{Username: sender, GroupIDs: groupIDs}, action.Params{})
	if err != nil {
		return commandaction.MessageDErreur(err)
	}
	return res.Message
}

// Version optimisée : aucune copie de slice inutile
func SplitArgsPreserveBlocks(input string) []string {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	res := make([]string, 0, len(parts))
	for i := 0; i < len(parts); {
		arg := parts[i]
		if strings.HasPrefix(arg, "--") {
			key := arg
			i++
			start := i
			for i < len(parts) && !strings.HasPrefix(parts[i], "--") {
				i++
			}
			res = append(res, key)
			if i > start {
				res = append(res, strings.Join(parts[start:i], " "))
			}
		} else {
			res = append(res, arg)
			i++
		}
	}
	return res
}

func HandleClientCLI(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logs.Write_Log("ERROR", fmt.Sprintf("Erreur fermeture connexion : %v", err))
		}
	}()

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Println("Erreur lecture :", err)
		return
	}

	command := strings.TrimSpace(string(buf[:n]))
	result := ExecuteCommand(command, "vaultaire")

	if _, err := conn.Write([]byte(result + "\n")); err != nil {
		logs.Write_Log("ERROR", fmt.Sprintf("Erreur envoi client : %v", err))
	}
}
