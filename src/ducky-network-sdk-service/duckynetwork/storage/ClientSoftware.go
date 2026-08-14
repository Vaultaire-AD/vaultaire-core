package storage

// SoftwarePath a rejoint KeyPath.go, avec sa résolution par variable
// d'environnement. Il n'était lu nulle part : le chemin réel se déduisait de
// KeyPath, et cette variable annonçait un emplacement différent de celui
// effectivement utilisé.
var Computeur_ID string
var LogicielType string
var IsServeur bool

// Persistent commande la RECONNEXION, rien d'autre.
//
// À ne pas confondre avec IsServeur, qui décrit la MACHINE — serveur membre du
// domaine — et vient de client_software.yaml. Les deux étaient confondus : un
// service, pour qui l'enrôlement écrit isServeur=false, tournait donc en mode
// une-passe et ne se reconnectait jamais après une coupure.
//
// Un service veut Persistent ; un utilitaire à usage unique ne le veut pas.
var Persistent bool
var SessionIntegritykey string

// VersionComposant est la version du PROGRAMME qui embarque ce socle.
//
// # Pourquoi une variable posée par le binaire, et non un import
//
// Le socle ne peut pas lire `vaultaire_client/version` : l'agent importe le
// SDK, l'inverse serait un cycle. Et un socle qui connaîtrait le nom de ses
// consommateurs ne serait plus un socle.
//
// C'est le même motif que Computeur_ID et DemarrerSessionMachine : ce que le
// programme sait de lui-même descend, il ne remonte pas.
//
// # Vide n'est pas une anomalie
//
// Un service qui ne la pose pas envoie une version vide, et le core l'affiche
// « inconnue ». C'est une information — un binaire qui ne se déclare pas — et
// non une raison de refuser sa connexion.
//
// Posée par le binaire au démarrage, AVANT l'ouverture de la session : la
// version part dans l'inventaire 02_12, émis dès l'authentification.
var VersionComposant string

type ClientSoftware struct {
	NewClient struct {
		Computeur_id  string `yaml:"computeur_id"`
		Logiciel_type string `yaml:"logiciel_type"`
		IsServeur     bool   `yaml:"isServeur"`
	} `yaml:"client_software"`
}
