package clusterstorage

import "time"

type Node struct {
	ID            int
	Hostname      string
	FQDN          string
	IPAddress     string
	Role          string
	Status        string
	VersionCode   string
	Capabilities  string // JSON string
	LastHeartbeat time.Time

	// Port sur lequel ce nœud écoute le protocole Ducky.
	//
	// La table n'en portait aucun : `capabilities` contenait parfois un
	// `{"port": …}` que rien ne lisait. Une liste d'adresses sans port n'est pas
	// une liste de nœuds joignables — l'agent devait deviner, donc supposer que
	// tout le parc écoute au même endroit.
	Port int

	// Priorite ordonne les nœuds de même nature. Plus petit = servi plus tôt.
	//
	// Zéro vaut « sans préférence » et se range après les valeurs explicites :
	// c'est ce qui permet d'ajouter une priorité à un seul nœud sans avoir à en
	// donner une à tous les autres.
	Priorite int

	// ExposeAuxAgents retire ce nœud de la liste distribuée aux agents.
	//
	// VRAI PAR DÉFAUT, et ce n'est PAS un contrôle d'accès : le drapeau retire
	// une adresse d'une liste, il n'empêche personne de se connecter. Le pare-feu
	// reste ce qui protège un core.
	//
	// Il sert à sortir un nœud de la rotation — maintenance, core réservé à
	// l'administration — sans le désenregistrer du cluster, ce qui le ferait
	// disparaître des vues de supervision au moment précis où on le surveille.
	ExposeAuxAgents bool

	// Empreinte de la clé publique de ce nœud, au format « SHA256:… ».
	//
	// Déclarée par le nœud lui-même à son enregistrement. Elle voyage dans la
	// liste distribuée aux agents : sans elle, un agent qui apprend l'adresse
	// d'un core devrait accepter sa clé en aveugle à la première connexion.
	Empreinte string

	// VersionSDK est celle du socle réseau lié à ce nœud.
	//
	// `VersionCode` porte déjà la version du PROGRAMME. Celle-ci répond à
	// l'autre question : avec quel SDK l'image a-t-elle été construite. Les deux
	// ne bougent pas ensemble, et un seul numéro pour les deux mentirait sur
	// l'un ou sur l'autre.
	//
	// Vide pour un core : il n'embarque pas le SDK — c'est lui qui juge les
	// clients, il ne partage pas leur socle.
	VersionSDK string
}
