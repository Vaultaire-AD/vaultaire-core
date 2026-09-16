package clusterstorage

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Validation de l'adresse et du port d'exposition d'un nœud.
//
// # Ce que cette validation protège
//
// L'adresse déclarée ici est distribuée à TOUT LE PARC par la trame 04_04, et
// chaque agent l'ajoute à sa liste de serveurs joignables. Une valeur mal formée
// n'est donc pas une erreur de saisie qu'on corrige à l'écran suivant : c'est
// une entrée que des centaines de machines vont tenter, échouer à joindre, et
// réessayer au cycle suivant.
//
// La validation est donc faite À L'ÉCRITURE, une fois, plutôt qu'à la lecture
// sur chaque chemin qui sert la liste. Une donnée acceptée en base est une
// donnée que tout le reste du code a le droit de croire.
//
// # Ce qu'elle ne protège pas
//
// Rien ne vérifie que l'adresse MÈNE au nœud : le core n'est pas forcément
// placé pour le savoir, et l'essayer depuis le core validerait le chemin du core
// et non celui des agents. Une adresse fausse mais bien formée est acceptée, et
// se voit à ce que les agents n'y arrivent pas.

// Bornes du champ d'adresse.
const (
	// MaxLongueurAdressePublique suit la colonne VARCHAR(255). Vérifié ici plutôt
	// que laissé à MySQL : selon le mode SQL, une valeur trop longue est
	// TRONQUÉE au lieu d'être refusée — le parc recevrait alors une adresse
	// coupée, syntaxiquement plausible et jamais joignable.
	MaxLongueurAdressePublique = 255
	// MaxLongueurEtiquetteDNS est la borne d'un label, fixée par la RFC 1035.
	MaxLongueurEtiquetteDNS = 63
)

// etiquetteDNS borne une étiquette de nom de domaine.
//
// Lettres, chiffres et tirets ; ni tiret en tête ni en queue. Le souligné est
// refusé : il est courant dans les enregistrements de service (_ldap._tcp) mais
// n'a rien à faire dans un nom d'hôte, et l'accepter ici laisserait passer des
// saisies qui ne résoudront jamais.
var etiquetteDNS = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// ValiderAdressePublique contrôle une adresse déclarée et rend sa forme propre.
//
// Une chaîne vide est VALIDE et rend une chaîne vide : c'est ainsi qu'on retire
// une déclaration pour revenir à l'adresse que le nœud annonce. Refuser le vide
// obligerait à supprimer et réenregistrer le nœud pour défaire une erreur de
// saisie.
func ValiderAdressePublique(brut string) (string, error) {
	adresse := strings.TrimSpace(brut)
	if adresse == "" {
		return "", nil
	}
	if len(adresse) > MaxLongueurAdressePublique {
		return "", fmt.Errorf("adresse trop longue : %d caractères, maximum %d",
			len(adresse), MaxLongueurAdressePublique)
	}

	// Le port n'est pas accepté DANS l'adresse.
	//
	// Il a son propre champ, et deux endroits pour la même information finissent
	// toujours par se contredire : « 203.0.113.5:6666 » avec un port public à
	// 16666 ne se tranche pas. Le refus nomme le champ à employer, sinon la
	// saisie la plus naturelle est rejetée sans qu'on sache par quoi la
	// remplacer.
	//
	// Un IPv6 littéral contient des « : » sans porter de port : on ne se
	// prononce que sur les formes qui ressemblent réellement à « hôte:port ».
	if hote, port, err := net.SplitHostPort(adresse); err == nil && port != "" {
		return "", fmt.Errorf(
			"le port ne se déclare pas dans l'adresse : indiquez %q comme adresse "+
				"et %q dans le champ de port", hote, port)
	}

	// Une IP est acceptée telle quelle, sous sa forme normalisée. net.ParseIP
	// accepte des écritures équivalentes du même IPv6 ; les enregistrer telles
	// que saisies ferait que deux nœuds à la même adresse paraîtraient différents
	// dans les vues.
	if ip := net.ParseIP(adresse); ip != nil {
		return ip.String(), nil
	}

	// Sinon, un nom DNS. Le point final absolu est toléré et retiré : il est
	// correct en syntaxe DNS, et le garder ferait que « proxy.example.com. » et
	// « proxy.example.com » s'affichent comme deux valeurs distinctes.
	nom := strings.TrimSuffix(adresse, ".")
	if nom == "" {
		return "", fmt.Errorf("adresse invalide : %q", brut)
	}
	for _, etiquette := range strings.Split(nom, ".") {
		if etiquette == "" {
			return "", fmt.Errorf(
				"adresse invalide : %q comporte une étiquette vide (deux points consécutifs)", brut)
		}
		if len(etiquette) > MaxLongueurEtiquetteDNS {
			return "", fmt.Errorf(
				"adresse invalide : l'étiquette %q dépasse %d caractères",
				etiquette, MaxLongueurEtiquetteDNS)
		}
		if !etiquetteDNS.MatchString(etiquette) {
			return "", fmt.Errorf(
				"adresse invalide : %q n'est ni une adresse IP ni un nom DNS "+
					"(étiquette fautive : %q)", brut, etiquette)
		}
	}
	return nom, nil
}

// ValiderPortPublic contrôle un port déclaré.
//
// Une chaîne vide rend zéro sans erreur : c'est ainsi qu'on retire la
// déclaration pour revenir au port que le nœud annonce écouter.
//
// Zéro EXPLICITE est accepté et vaut la même chose. Le distinguer du vide
// obligerait à expliquer la nuance dans l'interface, alors que « 0 » et « rien »
// veulent dire la même chose pour qui remplit le champ.
func ValiderPortPublic(brut string) (int, error) {
	texte := strings.TrimSpace(brut)
	if texte == "" {
		return 0, nil
	}

	port, err := strconv.Atoi(texte)
	if err != nil {
		return 0, fmt.Errorf("port invalide : %q n'est pas un nombre", brut)
	}
	if port < 0 || port > 65535 {
		return 0, fmt.Errorf("port invalide : %d est hors de 0-65535", port)
	}
	return port, nil
}

// AdresseAffichee rend « hôte:port » pour les vues et les journaux.
//
// Les crochets d'un IPv6 littéral sont posés ici : « fd00::1:6666 » est
// illisible et ambigu, « [fd00::1]:6666 » ne l'est pas. C'est aussi la forme que
// l'agent doit composer, donc celle qu'on veut voir à l'écran quand on cherche
// pourquoi il n'y arrive pas.
func AdresseAffichee(hote string, port int) string {
	if strings.TrimSpace(hote) == "" {
		return ""
	}
	if port <= 0 {
		return hote
	}
	return net.JoinHostPort(hote, strconv.Itoa(port))
}
