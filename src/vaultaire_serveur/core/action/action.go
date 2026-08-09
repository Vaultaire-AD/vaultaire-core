// Package action définit les actions métier de Vaultaire, une seule fois.
//
// # Le problème qu'il résout
//
// Créer un utilisateur s'écrivait à DEUX endroits : dans `command_create` pour
// la ligne de commande, et dans `web_admin_pages.go` pour l'interface web.
//
// Ce n'étaient pas deux copies mais deux comportements. Le web validait la date
// de naissance, la commande non. La commande déduisait prénom et nom d'un point
// dans l'identifiant, le web non. Le web exigeait un mot de passe non vide, la
// commande l'acceptait vide.
//
// Autrement dit, la même demande n'aboutissait pas au même compte selon la porte
// empruntée. Aucune des deux n'était fausse en soi ; c'est leur coexistence qui
// l'était, parce que rien ne signalait l'écart et que chaque correction n'en
// réparait qu'une moitié.
//
// # Le second problème, plus grave
//
// Le contrôle des droits était FAIL-OPEN côté web :
//
//	actionKey := ""
//	switch action {
//	case "add_user": actionKey = "write:add:user"
//	...
//	}
//	if actionKey != "" {          // une action absente du switch passe SANS contrôle
//	    ... vérification RBAC ...
//	}
//
// Une action oubliée dans cette table s'exécutait sans permission, sans erreur
// et sans trace. L'oubli ne se voyait donc jamais — ni à la compilation, ni à
// l'exécution, ni dans les journaux.
//
// Ici, la clé RBAC fait partie de la DÉFINITION de l'action. Une action sans clé
// est refusée à l'enregistrement, donc n'existe pas ; une action inconnue est
// refusée à l'exécution. L'oubli devient impossible au lieu d'être improbable.
// C'est le même parti que le catalogue `core/clienttype`.
//
// # Ce que ce paquet ne fait pas
//
// Il ne connaît ni HTTP ni terminal. Une action reçoit des paramètres nommés et
// rend un résultat ; `command` le met en forme pour un terminal, le serveur web
// pour un gabarit HTML ou du JSON.
//
// Cette ignorance est la condition du reste : dès qu'une action saurait qu'elle
// répond à une requête HTTP, la ligne de commande cesserait de pouvoir
// l'appeler, et le doublon reviendrait par la porte qu'on vient de fermer.
package action

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Params porte les valeurs d'entrée d'une action, nommées.
//
// Une map de chaînes plutôt qu'une structure par action : les deux sources sont
// déjà des chaînes nommées — `r.FormValue("username")` d'un côté, les arguments
// analysés de l'autre. Convertir vers un type fort se fait DANS l'action, où la
// règle de validation est écrite une fois pour les deux appelants.
//
// C'est aussi ce qui permet au registre de rester générique : il n'a pas à
// connaître la forme des paramètres de chaque action pour les acheminer.
type Params map[string]string

// Get rend une valeur nettoyée de ses espaces de bordure.
//
// Le nettoyage est fait ici plutôt que dans chaque action, parce que son oubli
// ne se voit pas : un nom d'utilisateur suivi d'un espace crée un compte
// distinct, visuellement identique au premier.
func (p Params) Get(nom string) string {
	return strings.TrimSpace(p[nom])
}

// Brut rend la valeur sans nettoyage, pour les rares champs où les espaces de
// bordure sont significatifs — un mot de passe, notamment. Les rogner
// empêcherait l'utilisateur de se connecter avec ce qu'il a réellement saisi,
// et le message d'erreur ne l'expliquerait pas.
func (p Params) Brut(nom string) string {
	return p[nom]
}

// Presente indique si le paramètre a été fourni, même vide.
//
// La distinction compte pour les mises à jour partielles : « champ absent »
// signifie ne pas y toucher, « champ présent et vide » signifie effacer.
func (p Params) Presente(nom string) bool {
	_, ok := p[nom]
	return ok
}

// Appelant décrit qui demande l'action.
type Appelant struct {
	// Username sert aux journaux et aux règles qui dépendent de l'identité —
	// ne pas se supprimer soi-même, par exemple.
	Username string

	// GroupIDs porte les droits. Résolu par l'appelant, pas ici : la ligne de
	// commande et le web l'obtiennent au même endroit, mais à des moments
	// différents de leur cycle.
	GroupIDs []int
}

// Resultat est ce qu'une action réussie produit.
type Resultat struct {
	// Message est une phrase destinée à un humain, employée telle quelle par la
	// ligne de commande et affichée par le web.
	Message string

	// Donnees porte le résultat structuré, quand il y en a un — une liste
	// d'utilisateurs, une fiche. Nil pour les actions qui ne rendent qu'un
	// compte rendu.
	//
	// C'est ce champ qui rend l'unification possible : sans lui, le web devrait
	// analyser du texte destiné à un terminal pour en extraire des données,
	// et retomberait aussitôt sur son propre accès à la base.
	Donnees any
}

// PorteeFunc détermine les domaines sur lesquels le droit est exigé.
//
// # Pourquoi ce n'est pas une simple liste
//
// La portée dépend de la CIBLE, connue seulement à l'exécution : modifier
// « alice » exige le droit sur les domaines d'alice, pas sur un domaine fixé à
// l'écriture de l'action.
//
// Une erreur d'inattention consisterait à rendre une liste vide quand la cible
// n'appartient à aucun domaine. `CheckPermissionsAllDomains` traite alors la
// demande comme globale, ce qui est le comportement voulu — mais il faut le
// vouloir. Voir PorteeGlobale.
type PorteeFunc func(p Params) ([]string, error)

// PorteeGlobale exige le droit sur « * ».
//
// Pour les actions qui ne visent aucune entité en particulier : régénérer un
// certificat, lire l'état du serveur. Un délégué d'un seul domaine ne doit pas
// pouvoir les déclencher, puisque leur effet dépasse son périmètre.
func PorteeGlobale(Params) ([]string, error) { return []string{"*"}, nil }

// Definition décrit une action métier.
type Definition struct {
	// Nom identifie l'action, sous la forme « objet.verbe » : « user.create »,
	// « group.add_user ». Cette forme se lit dans les journaux et se retrouve
	// dans les formulaires web.
	Nom string

	// CleRBAC est la permission exigée.
	//
	// Obligatoire, SAUF si ExigeSuperadmin est vrai — voir ce champ. C'est le
	// cœur du parti fail-closed : tant que la clé vivait dans une table séparée
	// de l'action, on pouvait ajouter l'une sans l'autre ; ici, une action qui
	// ne déclare aucun contrôle est refusée au démarrage, bruyamment.
	CleRBAC string

	// ExigeSuperadmin réserve l'action aux membres du groupe protégé.
	//
	// # Pourquoi ce champ existe
	//
	// Certaines opérations ne visent aucune entité de l'annuaire. Supprimer le
	// certificat TLS de LDAPS, par exemple, interrompt le service pour tout le
	// monde — mais un certificat ne porte pas de domaine, donc aucune clé RBAC
	// ne le couvre et aucune délégation ne s'y applique proprement.
	//
	// La première version du registre exigeait une clé RBAC dans tous les cas.
	// C'était confondre le principe avec son application : ce qui doit être
	// impossible, c'est qu'une action n'ait AUCUN contrôle déclaré — pas qu'elle
	// utilise un autre contrôle que le RBAC.
	//
	// Une action peut donc déclarer soit une clé, soit l'appartenance au groupe
	// protégé, soit les DEUX — auquel cas les deux sont exigées, ce qui est plus
	// strict et jamais moins.
	ExigeSuperadmin bool

	// ExigeSuperadminSi ajoute l'exigence d'appartenance SELON LES PARAMÈTRES.
	//
	// # Le cas qui l'a rendu nécessaire
	//
	// Émettre une clé d'enrôlement demande « write:create:client ». Mais une
	// clé visant un type qui porte l'assertion d'identité donne le pouvoir
	// d'agir au nom de n'importe quel utilisateur — ce qui ne se délègue pas par
	// une clé RBAC ordinaire. L'exigence dépend donc du type demandé, connu
	// seulement à l'exécution.
	//
	// # Pourquoi un champ SÉPARÉ de ExigeSuperadmin
	//
	// Parce qu'une exigence conditionnelle ne peut pas tenir lieu de contrôle
	// déclaré. Si elle le pouvait, une action sans clé RBAC dont la condition
	// rend « faux » s'exécuterait sans aucune vérification — et le registre ne
	// pourrait pas s'en apercevoir, puisqu'on ne peut pas inspecter une
	// fonction pour savoir si elle rend parfois faux.
	//
	// D'où la règle : ce champ AJOUTE une exigence, il n'en tient jamais lieu.
	// Une action qui n'a que lui, sans CleRBAC ni ExigeSuperadmin, est refusée
	// à l'enregistrement.
	ExigeSuperadminSi func(p Params) bool

	// Portee détermine les domaines sur lesquels CleRBAC est exigée.
	// OBLIGATOIRE, pour la même raison : une portée absente vaudrait « aucun
	// domaine », donc aucun contrôle effectif.
	Portee PorteeFunc

	// Resume décrit l'action en une ligne, pour l'aide et l'inventaire.
	Resume string

	// Executer fait le travail. Appelée UNIQUEMENT après contrôle des droits.
	Executer func(a Appelant, p Params) (Resultat, error)
}

// Registre contient les actions connues.
//
// Un type plutôt qu'un état global : les tests en construisent un vide et y
// enregistrent ce qu'ils veulent, sans que l'ordre d'exécution des tests ne
// dépende d'un état partagé — source classique d'échecs qui n'apparaissent
// qu'une fois sur dix.
type Registre struct {
	mu      sync.RWMutex
	actions map[string]Definition
}

// NouveauRegistre rend un registre vide.
func NouveauRegistre() *Registre {
	return &Registre{actions: make(map[string]Definition)}
}

// Enregistrer ajoute une action, en refusant tout ce qui est incomplet.
//
// Les refus sont des erreurs et non des avertissements : une action mal définie
// qui s'enregistrerait quand même serait exactement le défaut qu'on corrige —
// quelque chose qui manque sans que rien ne le signale.
func (r *Registre) Enregistrer(d Definition) error {
	if d.Nom == "" {
		return fmt.Errorf("action sans nom")
	}
	if d.Executer == nil {
		return fmt.Errorf("action %q sans fonction d'exécution", d.Nom)
	}
	// ExigeSuperadminSi ne compte PAS ici, délibérément : une exigence
	// conditionnelle peut ne pas s'appliquer, auquel cas l'action tournerait
	// sans contrôle. Voir le commentaire de ce champ.
	if strings.TrimSpace(d.CleRBAC) == "" && !d.ExigeSuperadmin {
		return fmt.Errorf(
			"action %q sans contrôle déclaré : ni clé RBAC, ni ExigeSuperadmin. "+
				"Une action qui ne déclare aucun contrôle s'exécuterait sans vérification — "+
				"c'est précisément le défaut que ce registre corrige. "+
				"ExigeSuperadminSi ne suffit pas : sa condition peut être fausse", d.Nom)
	}
	if d.Portee == nil {
		return fmt.Errorf(
			"action %q sans portée : sans domaines à vérifier, le contrôle du droit %q "+
				"ne porterait sur rien. Utilisez PorteeGlobale pour les actions sans cible.",
			d.Nom, d.CleRBAC)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if _, existe := r.actions[d.Nom]; existe {
		// Deux définitions du même nom : l'une écraserait l'autre selon l'ordre
		// d'enregistrement, donc selon l'ordre des fichiers. C'est le genre de
		// dépendance invisible qui produit un comportement différent après un
		// simple renommage de fichier.
		return fmt.Errorf("action %q déjà enregistrée", d.Nom)
	}
	r.actions[d.Nom] = d
	return nil
}

// MustEnregistrer arrête le programme si l'enregistrement échoue.
//
// Employée au démarrage, sur des définitions écrites en dur. Un échec y traduit
// une faute de programmation, pas une condition d'exécution : démarrer quand
// même laisserait tourner un serveur dont une action est absente ou non
// contrôlée, et l'absence ne se verrait qu'au moment où quelqu'un en aurait
// besoin.
func (r *Registre) MustEnregistrer(d Definition) {
	if err := r.Enregistrer(d); err != nil {
		panic("action: " + err.Error())
	}
}

// Definitions rend l'inventaire, trié par nom.
//
// Sert à l'aide, à l'inventaire des droits, et aux tests qui vérifient que
// chaque action déclare bien une clé RBAC valide.
func (r *Registre) Definitions() []Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]Definition, 0, len(r.actions))
	for _, d := range r.actions {
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nom < out[j].Nom })
	return out
}

// Definition rend une action par son nom.
func (r *Registre) Definition(nom string) (Definition, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.actions[nom]
	return d, ok
}

// ErrInconnue signale une action absente du registre.
//
// Type distinct : l'appelant doit pouvoir la distinguer d'un échec métier. Une
// action inconnue demandée par le web trahit un formulaire périmé ; demandée par
// la ligne de commande, une faute de frappe. Ni l'un ni l'autre n'est une erreur
// de l'action elle-même.
type ErrInconnue struct{ Nom string }

func (e *ErrInconnue) Error() string {
	return fmt.Sprintf("action inconnue : %q", e.Nom)
}

// ErrRefusee signale un droit insuffisant.
type ErrRefusee struct {
	Action string
	Cle    string
	Motif  string
}

func (e *ErrRefusee) Error() string {
	return fmt.Sprintf("permission refusée pour %s (%s) : %s", e.Action, e.Cle, e.Motif)
}

// VerificateurDroits contrôle qu'un appelant détient une permission sur des
// domaines donnés.
//
// Une interface plutôt qu'un appel direct à `permission` : les tests peuvent
// alors vérifier le comportement du registre — ce qu'il exige, ce qu'il refuse,
// ce qu'il journalise — sans base de données.
//
// Sans cela, les tests du contrôle d'accès demanderaient un annuaire complet,
// donc ne seraient pas écrits, donc le contrôle ne serait pas testé. C'est
// exactement ce qui s'est passé pour le module web : cinq mille lignes, aucun
// test.
type VerificateurDroits interface {
	// Autorise rend (true, "") si l'appelant détient `cle` sur TOUS les
	// domaines listés. Le second retour porte le motif du refus.
	Autorise(groupIDs []int, cle string, domaines []string) (bool, string)
}

// VerificateurSuperadmin contrôle l'appartenance au groupe protégé.
//
// Interface distincte de VerificateurDroits parce que la question est d'une
// autre nature : « détient-il ce droit sur ce périmètre » et « fait-il partie
// de ce groupe » ne se répondent pas de la même façon et ne se délèguent pas.
//
// Un exécuteur dépourvu de ce vérificateur REFUSE les actions qui l'exigent,
// plutôt que de les laisser passer. Voir Executer.
type VerificateurSuperadmin interface {
	EstSuperadmin(username string) bool
}

// Journal reçoit les refus et les exécutions.
//
// Interface pour la même raison : un test doit pouvoir constater qu'un refus a
// été tracé. Un refus silencieux est presque aussi gênant qu'une absence de
// refus — on ne saurait pas qu'une tentative a eu lieu.
type Journal interface {
	Refus(msg string)
	Execution(msg string)
}

// Executeur applique une action après contrôle des droits.
type Executeur struct {
	Registre   *Registre
	Droits     VerificateurDroits
	Superadmin VerificateurSuperadmin
	Journal    Journal
}

// Executer contrôle les droits puis lance l'action.
//
// L'ordre est la garantie : il n'existe aucun chemin qui atteigne
// `d.Executer` sans être passé par la vérification, parce que la vérification
// est ici et non dans chaque action. Une action ne PEUT pas oublier son
// contrôle, puisqu'elle ne l'écrit pas.
func (e *Executeur) Executer(nom string, a Appelant, p Params) (Resultat, error) {
	if e.Registre == nil {
		return Resultat{}, fmt.Errorf("exécuteur sans registre")
	}
	if e.Droits == nil {
		// Refus plutôt qu'exécution sans contrôle. Un exécuteur mal câblé est
		// une faute de programmation ; la traiter en laissant passer les actions
		// rendrait le registre inutile au moment précis où il compte.
		return Resultat{}, fmt.Errorf("exécuteur sans vérificateur de droits : aucune action ne peut être autorisée")
	}

	d, ok := e.Registre.Definition(nom)
	if !ok {
		return Resultat{}, &ErrInconnue{Nom: nom}
	}

	// Appartenance au groupe protégé, quand l'action l'exige.
	//
	// Vérifiée AVANT le RBAC : c'est le contrôle le plus grossier et le moins
	// coûteux, et son refus est le plus explicite à lire dans un journal.
	exigeGroupeProtege := d.ExigeSuperadmin
	if !exigeGroupeProtege && d.ExigeSuperadminSi != nil {
		exigeGroupeProtege = d.ExigeSuperadminSi(p)
	}

	if exigeGroupeProtege {
		if e.Superadmin == nil {
			// Refus plutôt qu'exécution. Un exécuteur sans ce vérificateur ne
			// peut pas répondre à la question posée ; laisser passer
			// reviendrait à traiter l'ignorance comme une autorisation.
			return Resultat{}, fmt.Errorf(
				"action %s réservée au groupe protégé, mais l'exécuteur n'a pas de "+
					"vérificateur d'appartenance : refus", nom)
		}
		if !e.Superadmin.EstSuperadmin(a.Username) {
			refus := &ErrRefusee{
				Action: nom,
				Cle:    "appartenance au groupe protégé",
				Motif:  "réservé aux membres du groupe protégé",
			}
			if e.Journal != nil {
				e.Journal.Refus(fmt.Sprintf(
					"action %s refusée à %s : réservée aux membres du groupe protégé",
					nom, a.Username))
			}
			return Resultat{}, refus
		}
	}

	domaines, err := d.Portee(p)
	if err != nil {
		return Resultat{}, fmt.Errorf("portée de %s indéterminable : %w", nom, err)
	}

	// Le RBAC ne s'applique que si une clé est déclarée. Une action réservée au
	// groupe protégé peut n'en avoir aucune — les certificats n'étant pas des
	// entités d'annuaire, aucune clé ne les couvre.
	//
	// Ce `if` n'est PAS le fail-open corrigé plus haut : là-bas, la clé pouvait
	// être vide par OUBLI et le contrôle sautait en silence. Ici, une clé vide
	// n'est possible que si ExigeSuperadmin est vrai — vérifié à
	// l'enregistrement — donc un autre contrôle a déjà eu lieu.
	if d.CleRBAC != "" {
		autorise, motif := e.Droits.Autorise(a.GroupIDs, d.CleRBAC, domaines)
		if !autorise {
			refus := &ErrRefusee{Action: nom, Cle: d.CleRBAC, Motif: motif}
			if e.Journal != nil {
				e.Journal.Refus(fmt.Sprintf(
					"action %s refusée à %s : droit %s exigé sur %v — %s",
					nom, a.Username, d.CleRBAC, domaines, motif))
			}
			return Resultat{}, refus
		}
	}

	res, err := d.Executer(a, p)
	if e.Journal != nil {
		if err != nil {
			e.Journal.Execution(fmt.Sprintf("action %s par %s : échec — %v", nom, a.Username, err))
		} else {
			e.Journal.Execution(fmt.Sprintf("action %s par %s : %s", nom, a.Username, res.Message))
		}
	}
	return res, err
}
