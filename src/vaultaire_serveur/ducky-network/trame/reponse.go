package trame

import "strings"

// La composition des réponses envoyées à un CLIENT.
//
// # Le défaut que ce paquet ferme
//
// Les deux sens du protocole Ducky n'ont pas le même en-tête.
//
//	client → serveur   5 lignes : code, destination, clé de session, utilisateur, id du logiciel
//	serveur → client   3 lignes : code, destination, clé de session
//
// L'asymétrie est voulue : l'utilisateur et l'identifiant du logiciel disent au
// serveur QUI parle. Une réponse n'a pas à les répéter — le client sait qui il
// est, et le serveur a déjà lié la session à ce client.
//
// Mais rien ne l'imposait. Chaque réponse était composée à la main, par
// concaténation, et les quatre trames de cluster 04_02, 04_04, 04_06 et 04_08
// ont été écrites avec l'en-tête des REQUÊTES — cinq lignes. L'agent, qui lit à
// partir de la quatrième, prenait donc « vaultaire » pour la première ligne de
// contenu :
//
//	[WARNING] découverte : 04_04 : nombre de nœuds illisible ("vaultaire")
//
// # Pourquoi cela n'a pas été vu plus tôt
//
// Trois des quatre trames sont de simples accusés dont le contenu n'est jamais
// analysé : « ok », « ack ». Le décalage y est parfaitement invisible — le
// journal de l'agent disait « enregistrement du nœud confirmé par le core », et
// il avait raison, le code de trame est en première ligne dans les deux formats.
//
// Seule 04_04 porte un contenu que quelqu'un lit. C'est la seule qui a parlé.
//
// # Ce que ce paquet garantit, et ce qu'il ne garantit pas
//
// Il garantit la FORME de l'en-tête, pas la justesse du contenu. C'est déjà
// l'essentiel : une erreur de contenu se voit à la lecture de la trame, une
// erreur d'en-tête décale tout ce qui suit et se manifeste très loin de sa
// cause — ici, dans un analyseur de liste de nœuds qui a l'air fautif.
//
// Le paquet ne dépend de rien, pour rester importable par tous les gestionnaires
// sans cycle.

// DestinationParDefaut sert quand la requête n'en portait pas.
//
// La valeur importe peu — aucun client ne la vérifie — mais une ligne VIDE en
// deuxième position décalerait l'en-tête d'une ligne, ce qui est exactement le
// défaut que ce paquet ferme.
const DestinationParDefaut = "serveur_central"

// ReponseClient compose une trame à destination d'un client.
//
// Chaque élément de `contenu` devient une ligne. Un contenu vide donne une trame
// réduite à son en-tête, ce qui est le cas normal d'un accusé sans charge.
//
// # La destination est RENVOYÉE, pas choisie
//
// Elle vient de la requête. Les deux orthographes coexistent dans le code
// existant — « serveur_central » côté SSH, « server_central » côté cluster — et
// trancher ici ferait répondre à un client autre chose que ce qu'il a écrit. Ce
// champ n'est vérifié par personne ; le rôle de cette fonction est l'en-tête,
// pas l'uniformisation d'une étiquette.
func ReponseClient(code, destination, sessionKey string, contenu ...string) string {
	if strings.TrimSpace(destination) == "" {
		destination = DestinationParDefaut
	}
	entete := code + "\n" + destination + "\n" + sessionKey
	if len(contenu) == 0 {
		return entete
	}
	return entete + "\n" + strings.Join(contenu, "\n")
}
