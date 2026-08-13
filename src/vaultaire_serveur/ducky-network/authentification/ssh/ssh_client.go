package sshclient

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/database"
	dbgroups "vaultaire/core/database/db_groups"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/domain"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
)

func SSH_Client_Manager(trames_content storage.Trames_struct_client, duckysession *storage.DuckySession) string {
	message := ""
	switch trames_content.Message_Order[1] {
	case "01":
		message = SSH_SEND_Pubkey_AUTH(trames_content)
	case "04":
		message = SSH_SEND_SALT(trames_content)
	case "06":
		message = SSH_SEND_Fetch_Pubkey(trames_content)
	case "08":
		message = SSH_SEND_GroupSync(trames_content)
	default:

	}
	return message
}

// SSH_SEND_Pubkey_AUTH authentifie un compte du domaine pour une ouverture de
// session, et rend ses clés publiques.
//
//	Contenu attendu : <utilisateur@domaine>\n<mot de passe>
//
// # Ce qui a disparu : le défi HMAC
//
// L'échange se faisait en deux temps. Le poste demandait le SEL du compte
// (03_04), le serveur le lui donnait avec un nonce (03_05), le poste calculait
// SHA-256(sel‖mot de passe) puis en faisait la clé d'un HMAC sur le nonce, et
// n'envoyait que ce HMAC (03_01). Le mot de passe ne traversait jamais le
// réseau. Vu ainsi, c'était plus prudent que les trois autres portes.
//
// Vu de la base, c'était l'inverse. Le serveur devait recalculer le même HMAC,
// donc détenir la MÊME clé, donc l'empreinte stockée servait de clé. Une
// empreinte qui sert de clé n'est plus une empreinte : c'est un mot de passe.
// Qui lisait la colonne `password` — sauvegarde, injection SQL, accès à la
// machine — ouvrait une session SSH sur n'importe quel compte, sans rien
// casser, sans rien deviner. Le hachage ne protégeait de rien SUR CE CHEMIN.
//
// C'est aussi ce qui interdisait argon2id : le poste aurait dû le calculer à
// l'identique, donc recevoir les paramètres, et l'empreinte serait restée la
// clé — le défaut aurait survécu au changement d'algorithme.
//
// Le mot de passe transite donc maintenant dans le tunnel, comme sur les trois
// autres portes. La confidentialité repose sur la session Ducky, déjà chiffrée
// et authentifiée, et l'empreinte stockée redevient ce qu'elle doit être :
// vérifiable, pas rejouable.
//
// # Ce que ce chemin gagne au passage
//
// La limitation de débit. Elle protégeait le portail, le bind LDAP et la trame
// Ducky 02_03 ; cette porte-ci n'en avait pas. Elle prend désormais un mot de
// passe : la laisser sans compteur en ferait la porte à essayer.
func SSH_SEND_Pubkey_AUTH(trames_content storage.Trames_struct_client) string {
	content := strings.Split(trames_content.Content, "\n")
	if len(content) < 2 {
		// Le CONTENU n'est plus journalisé : il porte désormais le mot de passe.
		// L'ancienne version le recopiait dans le message d'erreur — inoffensif
		// tant que ce champ ne portait qu'une preuve HMAC, à ne surtout pas
		// conserver maintenant qu'il porte le secret lui-même.
		logs.Write_Log(
			"ERROR",
			fmt.Sprintf(
				"Malformed CHECK TRAME THAT IS SEND %s %s %s %s %s",
				trames_content.Destination_Server,
				trames_content.SessionIntegritykey,
				trames_content.Username,
				trames_content.Domain,
				trames_content.ClientSoftwareID,
			),
		)
		return "02_07\nserveur_central\n" +
			trames_content.SessionIntegritykey + "\n" + trames_content.Username + "\ninvalid request"
	}
	db := database.GetDatabase()
	sshUser, domaine := domain.ExctractDomainFromUsername(content[0])
	motDePasse := content[1]

	refus := func(raison string) string {
		return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" + sshUser + "@" + domaine + "\n" + raison
	}

	// LIMITATION DES TENTATIVES — avant tout le reste.
	//
	// La source est le ClientSoftwareID et non une adresse IP, pour la même
	// raison que sur la trame 02_03 : l'adresse est celle du poste, partagée par
	// tous ses utilisateurs, ou celle d'un proxy, auquel cas le parc entier
	// n'aurait qu'une seule source.
	//
	// Les compteurs sont ceux des autres portes. Un compteur par porte laisserait
	// l'attaquant freiné sur le portail repartir de zéro ici.
	source := trames_content.ClientSoftwareID
	if autorise, reste := ratelimit.Autorise(sshUser, source); !autorise {
		logs.Write_Log("SECURITY", sshUser+" : trop de tentatives depuis "+source+
			", encore "+reste.Round(time.Second).String())
		return refus("permission denied")
	}

	userid, err := dbusers.Get_User_ID_By_Username(db, sshUser)
	if err != nil {
		logs.Write_Log("WARNING", "SSH: compte inconnu "+sshUser+" depuis "+source)
		ratelimit.Echec(sshUser, source)
		return refus("permission denied")
	}

	valide, err := dbusers.VerifierMotDePasse(db, userid, motDePasse)
	if err != nil {
		// Panne de lecture, pas un mauvais mot de passe : aucun échec compté,
		// sinon une base indisponible freinerait tous les comptes du parc.
		logs.Write_Log("ERROR", "SSH: lecture du mot de passe impossible pour "+sshUser+" : "+err.Error())
		return refus("verification error")
	}
	if !valide {
		logs.Write_Log("WARNING", "SSH: mot de passe incorrect pour "+sshUser+" depuis "+source)
		ratelimit.Echec(sshUser, source)
		return refus("permission denied")
	}
	ratelimit.Reussite(sshUser, source)

	// KILL SWITCH : même un mot de passe valide ne rouvre pas un compte révoqué.
	// Ce contrôle vient APRÈS la vérification pour ne pas révéler l'état du
	// compte à qui n'en détient pas les identifiants.
	if permission.IsRevoked(sshUser) {
		logs.Write_Log("SECURITY", sshUser+" : mot de passe valide mais compte révoqué, accès SSH refusé sur "+trames_content.ClientSoftwareID)
		return refus("permission denied")
	}

	// Droit de se connecter au DOMAINE.
	//
	// Ce contrôle vivait dans SSH_SEND_SALT, qui a disparu avec le défi. Il ne
	// figurait nulle part ici : le supprimer sans le déplacer aurait ouvert
	// l'accès SSH à des comptes qu'une permission de domaine en écartait.
	if ok, _ := permission.CanUserConnectToDomain(sshUser + "@" + domaine); !ok || sshUser == "vaultaire" {
		logs.Write_Log("WARNING", sshUser+" : accès au domaine "+domaine+" refusé depuis "+source)
		return refus("permission denied")
	}

	// Droit de se connecter à CETTE MACHINE.
	can, err := dbusers.DidUserCanLogin(db, sshUser, trames_content.ClientSoftwareID)
	if err != nil || !can {
		logs.Write_Log("WARNING", sshUser+" permission denied for machine "+trames_content.ClientSoftwareID)
		return refus("permission denied")
	}

	sshkey, err := dbusers.Get_PublicKeys_ByUserID(db, userid)
	if err != nil {
		logs.Write_Log("ERROR", "Error retrieving SSH key for user "+sshUser)
		return refus("ssh key error")
	}
	isadmin, err := dbusers.IsUserAdmin(db, sshUser, trames_content.ClientSoftwareID)
	if err != nil {
		logs.Write_Log("ERROR", "Error checking admin status for user "+sshUser)
		return refus("admin check error")
	}

	// LES GROUPES DU COMPTE, rafraîchis à chaque connexion.
	//
	// # Pourquoi ici et pas dans une trame à part
	//
	// La question « à quels groupes appartient ce compte » n'a de réponse utile
	// qu'au moment où il ouvre une session : c'est là que la machine doit poser
	// ses appartenances locales. Une trame séparée ajouterait un aller-retour à
	// l'ouverture de session — celui-là même que la suppression du défi HMAC
	// vient de retirer — pour une donnée que le serveur a déjà en main.
	//
	// Rafraîchi à chaque connexion PAR CONSTRUCTION, donc : il n'y a pas de cache
	// à invalider ni de cadence à régler. Un utilisateur retiré d'un groupe le
	// perd sur la machine dès sa prochaine ouverture de session.
	//
	// # Une lecture qui échoue n'empêche pas la connexion
	//
	// Le compte est authentifié, son droit d'accès à la machine est vérifié : lui
	// refuser la session parce que la liste de ses groupes est illisible serait
	// disproportionné. Il ouvre sa session avec les appartenances de la fois
	// précédente, et l'incident part dans le journal.
	groupes, errG := dbgroups.NomsDesGroupesDeLUtilisateur(db, sshUser)
	if errG != nil {
		logs.Write_LogCode("WARNING", logs.CodeDBQuery,
			"SSH: groupes de "+sshUser+" illisibles ("+errG.Error()+") — session ouverte sans mise à jour")
		groupes = nil
	}

	sshkeyString := strings.Join(sshkey, "\n")
	logs.Write_Log("INFO", "SSH access granted for user "+sshUser+" (Admin: "+strconv.FormatBool(isadmin)+
		", groupes: "+strconv.Itoa(len(groupes))+")"+"| On client :"+trames_content.ClientSoftwareID)

	// La ligne des groupes porte un PRÉFIXE, et se place avant les clés.
	//
	// Les clés occupent « tout le reste » du contenu : il n'existe donc aucune
	// position après elles. Le préfixe permet à l'agent de reconnaître ce champ
	// et de ne pas le prendre pour une clé — et à un agent qui l'ignorerait de
	// n'écrire qu'une ligne inerte dans authorized_keys, que sshd passe.
	//
	// C'est le compromis assumé de la compatibilité descendante sur ce chemin,
	// qui en a déjà un : un agent resté à l'ancienne authentification reçoit
	// « obsolete client, update required » sur 03_04.
	return "03_02\nserveur_central\n" + trames_content.SessionIntegritykey + "\n" +
		sshUser + "@" + domaine + "\n" +
		strconv.FormatBool(isadmin) + "\n" +
		PrefixeGroupes + strings.Join(groupes, ",") + "\n" +
		sshkeyString
}

// PrefixeGroupes ouvre la ligne des groupes dans la réponse 03_02.
//
// Exporté et nommé d'un seul côté : l'agent le reconnaît par la même chaîne, et
// une valeur recopiée dans les deux dépôts finirait par différer d'un caractère
// — auquel cas l'agent prendrait la ligne pour une clé publique, en silence.
const PrefixeGroupes = "groups:"

// SSH_SEND_SALT refuse : la trame 03_04 n'existe plus.
//
// Elle demandait le SEL d'un compte pour que le poste puisse dériver la clé du
// défi HMAC. Le défi a disparu (voir SSH_SEND_Pubkey_AUTH), donc plus personne
// n'a besoin du sel — et le distribuer serait un service rendu au seul attaquant
// qui prépare un dictionnaire hors ligne pour un compte précis.
//
// La fonction subsiste plutôt que d'être effacée, et répond explicitement, pour
// une raison de terrain : un agent resté à l'ancienne version enverra encore
// cette trame. Sans réponse, il attendrait sept secondes puis rendrait un
// « timeout » à PAM, et l'administrateur chercherait une panne réseau. Avec
// celle-ci, le journal des deux côtés nomme la cause.
func SSH_SEND_SALT(trames_content storage.Trames_struct_client) string {
	logs.Write_Log("WARNING",
		"Trame 03_04 reçue depuis "+trames_content.ClientSoftwareID+
			" : l'agent utilise l'ancienne authentification par défi. Mettre à jour vaultaire_client.")
	return "03_03\nserveur_central\n" + trames_content.SessionIntegritykey +
		"\nvaultaire@vaultaire\nobsolete client, update required"
}

func SSH_SEND_Fetch_Pubkey(trames_content storage.Trames_struct_client) string {
	content := strings.Split(strings.TrimSpace(trames_content.Content), "\n")
	if len(content) < 1 || content[0] == "" {
		logs.Write_Log("ERROR", "Malformed SSH fetch-key request")
		return "" // Pas de reponse si la requete est malformee
	}

	db := database.GetDatabase()
	sshUser, domaine := domain.ExctractDomainFromUsername(content[0])

	// 1. Verification des droits (peut-il se connecter sur cette machine ?)
	// KILL SWITCH inclus : les clés publiques d'un compte révoqué ne sont plus
	// distribuées, sans quoi l'agent les réinstallerait dans authorized_keys.
	if permission.IsRevoked(sshUser) {
		logs.Write_Log("SECURITY", sshUser+" : demande de clés publiques sur un compte révoqué (fetch-key)")
		return ""
	}
	can, err := dbusers.DidUserCanLogin(db, sshUser, trames_content.ClientSoftwareID)
	if err != nil || !can || sshUser == "vaultaire" {
		logs.Write_Log("WARNING", sshUser+" permission denied for machine "+trames_content.ClientSoftwareID+" (fetch-key)")
		return "" // Pas de reponse : on ne revele pas si le user existe ou non
	}

	// 2. Recuperation des clés publiques
	userid, err := dbusers.Get_User_ID_By_Username(db, sshUser)
	if err != nil {
		logs.Write_Log("ERROR", "User not found: "+sshUser+" (fetch-key)")
		return ""
	}

	sshkeys, err := dbusers.Get_PublicKeys_ByUserID(db, userid)
	if err != nil {
		logs.Write_Log("ERROR", "Error retrieving SSH key for user "+sshUser+" (fetch-key)")
		return ""
	}

	logs.Write_Log("INFO", "Cles publiques transmises pour "+sshUser+"@"+domaine+" (fetch-key)")

	sshkeyString := strings.Join(sshkeys, "\n")
	return "03_07\nserveur_central\n" + trames_content.SessionIntegritykey + "\nvaultaire\n" + "\n" + sshUser + "@" + domaine + "\n" + sshkeyString
}
