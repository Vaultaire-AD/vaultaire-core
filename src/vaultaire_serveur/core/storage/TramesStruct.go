package storage

import "net"

type Trames_struct_client struct {
	Message_Order       []string
	Destination_Server  string
	SessionIntegritykey string
	Username            string
	Domain              string
	ClientSoftwareID    string
	Content             string
}

type Trames_struct struct {
	Message_Order      []string
	Destination_Server string
	Content            string
}

type DuckySession struct {
	// SessionID identifie cette connexion de façon unique. Il est généré à
	// l'accept() (voir sessionmgr.NewSessionID), puis aligné sur le
	// SessionIntegritykey réel une fois la poignée de main initiale terminée
	// (voir sessionmgr.Manager.Rekey), pour rester grep-able de façon
	// interchangeable entre les logs et le protocole réseau.
	SessionID  string
	Conn       net.Conn
	IsSafe     bool
	SessionKey []byte

	// BoundClientSoftwareID est l'identifiant de machine lié à cette connexion,
	// figé lors de la poignée de main 01_01.
	//
	// Il n'est pas « annoncé » au sens d'une donnée à croire sur parole : la
	// réponse 01_02 est chiffrée avec la clé publique de CET identifiant (voir
	// sendmessage.SendMessage, branche IsSafe == false) et transporte la clé de
	// session. Un client qui annonce l'identifiant d'une autre machine ne peut
	// donc pas déchiffrer 01_02, n'obtient pas la clé de session, et aucune de
	// ses trames suivantes ne sera lisible par le serveur. La possession est
	// prouvée par construction, pas par une vérification supplémentaire.
	//
	// Ce que ce champ apporte : les trames suivantes portent elles aussi un
	// ClientSoftwareID, et rien n'obligeait qu'il soit le même. Un client
	// légitimement authentifié pouvait réclamer les GPO — donc les règles sudo,
	// la configuration SSH et le contenu des fichiers déployés — d'une machine
	// quelconque du parc. Comparer chaque trame à cette valeur ferme cet écart.
	BoundClientSoftwareID string

	// EnrollmentComputeurID et EnrollmentClientType portent l'état d'un
	// enrôlement en cours, entre 01_05 et 01_07.
	//
	// # Pourquoi dans la session et pas dans une table
	//
	// L'enrôlement se déroule sur UNE connexion, en deux allers-retours. Le lier
	// à la session le fait expirer avec elle : une connexion coupée entre 01_05
	// et 01_07 ne laisse rien derrière. Une table de travail garderait des
	// enrôlements à moitié faits qu'il faudrait balayer.
	//
	// Pendant cet intervalle, SessionKey porte la clé TEMPORAIRE fournie par le
	// client en 01_05 et IsSafe vaut true : le déchiffrement symétrique ordinaire
	// lit donc 01_07 sans traitement particulier.
	//
	// BoundClientSoftwareID reste VIDE tout du long, et c'est voulu : la machine
	// n'est liée qu'à la poignée de main 01_01, sur une connexion neuve, une fois
	// l'enrôlement terminé. Un type vide n'émet rien (fail-closed), ce qui enferme
	// la connexion d'enrôlement dans les seules trames autorisées.
	EnrollmentComputeurID string
	EnrollmentClientType  string

	// BoundClientType est le type de programme de cette machine, lu en base à
	// la poignée de main et figé pour toute la connexion.
	//
	// Il décide de ce que la session a le droit d'émettre (voir
	// core/clienttype et tramesmanager.Split_Action). Figé pour la même raison
	// que BoundClientSoftwareID : le relire à chaque trame laisserait une
	// modification concurrente changer les droits d'une session en cours.
	//
	// Vide tant que la poignée de main n'a pas eu lieu, ce qui interdit tout
	// par construction — un type inconnu n'émet rien.
	BoundClientType string
}
