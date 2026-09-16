package clusterstorage

import (
	"strings"
	"time"
)

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

	// AdressePublique est l'adresse par laquelle les AGENTS joignent ce nœud.
	//
	// # Pourquoi elle ne peut pas venir du nœud
	//
	// `IPAddress` est un FAIT, et le nœud est bien placé pour le déclarer : c'est
	// l'adresse qu'il voit de lui-même. Mais derrière une redirection NAT, dans
	// un conteneur, ou sur un hôte à plusieurs interfaces, ce n'est pas celle par
	// laquelle le parc l'atteint — et le nœud ne peut pas la connaître, puisqu'il
	// ne voit pas son infrastructure de l'extérieur.
	//
	// C'est donc une décision d'EXPLOITATION, déclarée par un administrateur, au
	// même titre que `Priorite` et `ExposeAuxAgents`. Comme elles, elle est
	// absente des requêtes d'enregistrement : sinon le nœud l'écraserait avec sa
	// propre vue à son prochain démarrage.
	//
	// # Champ séparé, et non un écrasement d'IPAddress
	//
	// Les deux répondent à des questions différentes — « où se croit-il » et « où
	// le joint-on » — et se réécrivent à des rythmes opposés. Garder le fait
	// permet aussi de voir l'écart, qui est souvent l'information utile quand une
	// connexion ne passe pas.
	//
	// Vide vaut « aucune déclaration » : c'est `IPAddress` qui est servie, donc
	// le comportement d'avant ce champ. IP ou nom DNS.
	AdressePublique string

	// PortPublic est le port par lequel les agents joignent ce nœud.
	//
	// Zéro vaut « aucune déclaration », et c'est `Port` qui est servi. Séparé de
	// l'adresse parce qu'une redirection translate souvent le port sans changer
	// l'hôte : les agents joignent 203.0.113.5:16666 un proxy qui écoute bien
	// sur 6666.
	PortPublic int

	// Proprietaire est le SEUL client autorisé à modifier cette ligne.
	//
	// # Le défaut que ce champ ferme
	//
	// `handleRegisterHost` lisait le hostname, l'IP et le RÔLE dans le contenu
	// de la trame 04_01, sans aucun lien avec la session authentifiée. Un proxy
	// enrôlé pouvait donc envoyer le hostname d'un core existant : l'upsert
	// écrasait sa ligne — adresse, port et EMPREINTE comprises — et la liste
	// servie aux agents annonçait dès lors l'empreinte de l'attaquant sous le
	// nom du core. Les agents l'apprenaient, la mettaient en tête de leur liste,
	// et s'y connectaient pour s'authentifier.
	//
	// # Deux formes
	//
	//	<client_software_id>   un nœud enregistré par le réseau (proxy, service)
	//	@core:<hostname>       un core qui se déclare lui-même, sans session
	//
	// Le préfixe « @ » est RÉSERVÉ : un propriétaire venu d'une session ne peut
	// pas commencer par lui. Sans cette réserve, un client dont l'identifiant
	// ressemblerait à « @core:… » revendiquerait la ligne d'un core.
	//
	// Par hostname et non une valeur unique pour tous les cores : sur un cluster
	// à plusieurs cores, un propriétaire commun laisserait chacun écrire la
	// ligne des autres — le défaut corrigé, sous une autre forme.
	Proprietaire string

	// Affin dit que ce nœud partage un groupe avec l'agent qui demande la liste.
	//
	// # Ce n'est PAS une colonne, et ce n'est pas une propriété du nœud
	//
	// L'affinité est une relation entre un nœud et un DEMANDEUR : le même nœud
	// est affin pour l'agent de Paris et ne l'est pas pour celui de Lyon. La
	// valeur est donc calculée au moment de servir la liste, et posée ici pour
	// que le tri et les vues n'aient pas à refaire l'intersection.
	//
	// Faux par défaut, ce qui donne exactement le comportement d'avant le lot 6 :
	// un tri sans affinité ordonne par rôle puis par priorité, comme auparavant.
	// Les chemins qui listent les nœuds SANS demandeur — la page cluster, `vlt
	// cluster list` — le laissent donc à faux, et c'est juste : hors d'une
	// demande, la question « affin ? » n'a pas de réponse.
	Affin bool

	// GroupesAffins porte les NOMS des groupes servis en priorité par ce nœud.
	//
	// Renseigné pour les vues seulement, et jamais sur le chemin de 04_04 : la
	// liste distribuée aux agents ne doit pas décrire l'organisation du parc à
	// toutes les machines. Un agent a besoin de savoir QUI joindre, pas
	// pourquoi ce nœud est là.
	GroupesAffins []string
}

// AdresseEffective rend l'adresse à annoncer aux agents.
//
// La déclaration de l'administrateur l'emporte sur ce que le nœud voit de
// lui-même. C'est tout l'objet du champ : le nœud se trompe forcément dès qu'il
// est derrière une redirection, et il n'a aucun moyen de le savoir.
func (n Node) AdresseEffective() string {
	if strings.TrimSpace(n.AdressePublique) != "" {
		return strings.TrimSpace(n.AdressePublique)
	}
	return n.IPAddress
}

// PortEffectif rend le port à annoncer aux agents.
//
// Indépendant de l'adresse, et c'est voulu : déclarer un port sans adresse est
// un cas réel — une redirection qui translate le port sur l'hôte que le nœud
// voit déjà correctement.
func (n Node) PortEffectif() int {
	if n.PortPublic > 0 {
		return n.PortPublic
	}
	return n.Port
}

// ExpositionDeclaree indique qu'un administrateur a redéclaré l'accès.
//
// Sert aux vues : afficher « 203.0.113.5:16666 » sans dire que l'adresse est
// déclarée ferait chercher longtemps pourquoi elle ne correspond pas à ce que la
// machine rapporte.
func (n Node) ExpositionDeclaree() bool {
	return strings.TrimSpace(n.AdressePublique) != "" || n.PortPublic > 0
}
