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
}
