package action

import (
	"fmt"

	"vaultaire/core/database"
	isprotected "vaultaire/core/database/is_protected"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Raccordement du registre au système de permissions et aux journaux réels.
//
// Ces adaptateurs sont volontairement minces : ils traduisent, ils ne décident
// pas. Toute la logique de contrôle vit dans Executeur, où elle est testable
// sans base de données — c'est ce qui permet aux tests du registre d'exister.

// DroitsVaultaire branche le registre sur core/permission.
type DroitsVaultaire struct{}

// Autorise exige le droit sur TOUS les domaines de la portée.
//
// CheckPermissionsAllDomains et non CheckPermissionsMultipleDomains : la
// nuance décide de la sécurité du contrôle.
//
// « Multiple » se satisfait d'un seul domaine correspondant. Pour une action qui
// vise une entité présente dans plusieurs domaines, cela reviendrait à laisser
// un délégué de Paris agir sur un compte qui détient aussi des droits à Lyon —
// son droit sur Paris suffirait à emporter la décision.
//
// « All » exige le droit partout où l'entité se trouve. C'est la seule lecture
// qui rend la délégation par domaine effective.
func (DroitsVaultaire) Autorise(groupIDs []int, cle string, domaines []string) (bool, string) {
	return permission.CheckPermissionsAllDomains(groupIDs, cle, domaines)
}

// AutoriseSurUnDomaine se satisfait d'un seul domaine correspondant.
//
// Réservé aux actions qui déclarent UnDomaineSuffit — donc aux lectures. Voir
// ce champ pour la raison : voir une entité et agir dessus ne sont pas la même
// décision, et l'interface web comme la ligne de commande faisaient déjà cette
// distinction avant le registre.
func (DroitsVaultaire) AutoriseSurUnDomaine(groupIDs []int, cle string, domaines []string) (bool, string) {
	return permission.CheckPermissionsMultipleDomains(groupIDs, cle, domaines)
}

// AutorisePartout répond « as-tu quelque chose à faire ici ? ».
//
// C'est la question que l'interface web posait déjà avant d'ouvrir une page —
// permission.HasActionAnywhere — mais que le registre ne posait nulle part. La
// page s'ouvrait donc, puis l'action qu'elle appelait refusait sur « * ».
//
// Le motif de refus nomme la clé et non un domaine : il n'y en a aucun à citer,
// et écrire « * : refusée » a fait chercher un problème de domaine là où il n'y
// avait qu'une absence totale de droit.
func (DroitsVaultaire) AutorisePartout(groupIDs []int, cle string) (bool, string) {
	if permission.HasActionAnywhere(groupIDs, cle) {
		return true, ""
	}
	return false, fmt.Sprintf(
		"le droit %s n'est accordé sur aucun domaine", cle)
}

// SuperadminVaultaire branche le registre sur le groupe protégé.
type SuperadminVaultaire struct{}

// EstSuperadmin vérifie l'appartenance au groupe protégé.
//
// Le refus est journalisé ICI plutôt que laissé au seul exécuteur : la tentative
// mérite une trace même si l'appelant décide ensuite de l'ignorer, et cette
// fonction est le seul endroit qui connaisse le nom du groupe concerné.
func (SuperadminVaultaire) EstSuperadmin(username string) bool {
	if isprotected.IsSuperadmin(database.GetDatabase(), username) {
		return true
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a tenté une action réservée aux membres du groupe %s",
		username, isprotected.ProtectedGroupName))
	return false
}

// JournalVaultaire écrit dans les journaux du serveur.
type JournalVaultaire struct{}

// Refus part en SECURITY et non en WARNING.
//
// Une tentative d'action sans droit n'est pas un incident d'exploitation : c'est
// soit une erreur de configuration des permissions, soit quelqu'un qui essaie.
// Les deux méritent d'être retrouvables en filtrant sur un seul niveau.
func (JournalVaultaire) Refus(msg string) {
	logs.Write_Log("SECURITY", msg)
}

func (JournalVaultaire) Execution(msg string) {
	logs.Write_Log("INFO", msg)
}

// Echec en WARNING : une écriture qui n'aboutit pas mérite d'être vue sans
// activer le niveau informatif, et de ne pas se confondre avec les écritures
// réussies quand on filtre.
func (JournalVaultaire) Echec(msg string) {
	logs.Write_Log("WARNING", msg)
}

// PorteeUtilisateur exige le droit sur les domaines du compte visé.
//
// Le paramètre lu est « username ». Une action qui nommerait sa cible autrement
// doit fournir sa propre portée — sans quoi le contrôle porterait sur une chaîne
// vide, donc sur les domaines de personne.
func PorteeUtilisateur(p Params) ([]string, error) {
	return domainesOuGlobal(permission.GetDomainListFromUsername(p.Get("username")))
}

// PorteeGroupe exige le droit sur les domaines du groupe visé, paramètre « group ».
func PorteeGroupe(p Params) ([]string, error) {
	return domainesOuGlobal(permission.GetDomainsFromGroupName(p.Get("group")))
}

// PorteeGroupeEtUtilisateur exige le droit sur les domaines des DEUX.
//
// # Pourquoi l'union, et pas l'un ou l'autre
//
// Rattacher un utilisateur à un groupe a deux effets, et chacun justifiait une
// portée différente :
//
//   - l'utilisateur gagne les droits du groupe → ce sont ses domaines à lui qui
//     sont touchés ;
//   - le groupe distribue ses droits à un membre de plus → ce sont les domaines
//     du groupe qui sont engagés.
//
// Les trois implémentations existantes avaient tranché différemment, sans que ce
// soit visible :
//
//	add -u alice -g paris      domaines de l'UTILISATEUR
//	add -c poste-1 -g paris    domaines du GROUPE
//	interface web              domaines du GROUPE
//
// Un délégué de « paris » pouvait donc ajouter un compte de son domaine à un
// groupe de « lyon » depuis la ligne de commande — donc lui donner des droits sur
// lyon — mais pas depuis l'interface web. La même intention aboutissait ou non
// selon la porte empruntée.
//
// L'union exige le droit des deux côtés. C'est plus strict que chacune des trois
// versions, donc sûr ; et c'est le seul choix qui ne dépende pas de la façade.
//
// À vérifier chez vous : un délégué qui rattachait des comptes à des groupes
// d'un autre domaine perdra cette possibilité.
func PorteeGroupeEtUtilisateur(p Params) ([]string, error) {
	domainesGroupe, errG := permission.GetDomainsFromGroupName(p.Get("group"))
	domainesUser, errU := permission.GetDomainListFromUsername(p.Get("username"))

	// Une erreur de lecture d'un côté ne doit pas réduire la portée à l'autre :
	// ce serait affaiblir le contrôle au moment précis où l'on sait le moins de
	// choses. domainesOuGlobal exige alors le droit global.
	if errG != nil || errU != nil {
		return domainesOuGlobal(nil, fmt.Errorf("groupe : %v ; utilisateur : %v", errG, errU))
	}
	return domainesOuGlobal(unionDomaines(domainesGroupe, domainesUser), nil)
}

// PorteeGroupeEtClient : même raisonnement pour le rattachement d'une machine.
func PorteeGroupeEtClient(p Params) ([]string, error) {
	domainesGroupe, errG := permission.GetDomainsFromGroupName(p.Get("group"))
	domainesClient, errC := permission.GetDomainsFromClientByComputerID(p.Get("computeur_id"))

	if errG != nil || errC != nil {
		return domainesOuGlobal(nil, fmt.Errorf("groupe : %v ; machine : %v", errG, errC))
	}
	return domainesOuGlobal(unionDomaines(domainesGroupe, domainesClient), nil)
}

// unionDomaines fusionne sans doublon.
//
// Les doublons ne fausseraient pas le contrôle — CheckPermissionsAllDomains
// vérifierait deux fois le même domaine — mais ils apparaîtraient dans les
// journaux de refus, où l'on cherche justement à comprendre quels domaines
// étaient exigés.
func unionDomaines(a, b []string) []string {
	vus := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, liste := range [][]string{a, b} {
		for _, d := range liste {
			if d == "" || vus[d] {
				continue
			}
			vus[d] = true
			out = append(out, d)
		}
	}
	return out
}

// PorteeClient exige le droit sur les domaines de la machine visée,
// paramètre « computeur_id ».
func PorteeClient(p Params) ([]string, error) {
	return domainesOuGlobal(permission.GetDomainsFromClientByComputerID(p.Get("computeur_id")))
}

// permissionDomainesUtilisateur et permissionDomainesClient isolent les deux
// fonctions de core/permission employées par les portées des permissions.
//
// Indirection volontaire : elles portent des noms très proches
// (GetDomainslistFromUserpermission / GetDomainslistFromClientpermission) et
// les confondre donnerait un contrôle qui s'exerce sur les domaines de la
// mauvaise permission — sans erreur visible, puisque les deux rendent une liste
// de chaînes.
func permissionDomainesUtilisateur(nom string) ([]string, error) {
	return permission.GetDomainslistFromUserpermission(nom)
}

func permissionDomainesClient(nom string) ([]string, error) {
	return permission.GetDomainslistFromClientpermission(nom)
}

// domainesOuGlobal traduit « aucun domaine » en « droit global exigé ».
//
// # Pourquoi ce n'est pas un détail
//
// Une entité sans domaine — un compte fraîchement créé, un groupe non rattaché —
// rendrait une liste vide. Et CheckPermissionsAllDomains sur une liste vide
// n'a rien à vérifier : elle autoriserait tout le monde.
//
// L'entité la moins rattachée serait alors la plus accessible, ce qui est
// exactement l'inverse de l'intention. On exige donc le droit global, c'est-à-
// dire le plus fort, pour ce qu'on ne sait pas situer.
//
// Une erreur de lecture reçoit le même traitement : ne pas savoir dans quel
// domaine se trouve une entité n'autorise pas à agir dessus.
func domainesOuGlobal(domaines []string, err error) ([]string, error) {
	if err != nil {
		// L'erreur n'est pas propagée : la propager empêcherait l'action, alors
		// qu'un administrateur global doit pouvoir agir sur une entité dont le
		// rattachement est illisible — c'est même souvent pour la réparer.
		logs.Write_Log("DEBUG", fmt.Sprintf("action: domaines indéterminés (%v), droit global exigé", err))
		return []string{"*"}, nil
	}
	if len(domaines) == 0 {
		return []string{"*"}, nil
	}
	return domaines, nil
}

// Executeur par défaut, partagé par la ligne de commande et le serveur web.
//
// C'est le point où les deux façades se rejoignent : elles n'ont plus qu'un
// exécuteur, donc un seul chemin de contrôle des droits.
var (
	// Catalogue contient les actions de Vaultaire.
	//
	// Nommé Catalogue et non Registre : ce dernier est le nom du TYPE, et une
	// variable qui le porterait empêcherait d'écrire `var r Registre` dans le
	// même paquet. Le compilateur le refuse, ce qui est heureux — mais le
	// conflit se serait vu plus tard, dans un fichier qui n'aurait rien à voir.
	Catalogue = NouveauRegistre()

	// Defaut applique les actions du catalogue avec les droits et journaux
	// réels. C'est le point où la ligne de commande et le serveur web se
	// rejoignent : un seul exécuteur, donc un seul chemin de contrôle.
	Defaut = &Executeur{
		Registre:   Catalogue,
		Droits:     DroitsVaultaire{},
		Superadmin: SuperadminVaultaire{},
		Journal:    JournalVaultaire{},
		Perimetres: PerimetreVaultaire{},
	}
)

// EnregistrerTout garnit le catalogue partagé.
//
// Appelée une fois au démarrage du serveur. Un appel explicite plutôt qu'une
// cascade d'init() : l'ordre d'initialisation entre paquets dépendrait sinon de
// l'ordre des imports, et un import retiré ferait disparaître des actions sans
// la moindre erreur de compilation.
func EnregistrerTout() {
	EnregistrerActionsUtilisateur(Catalogue)
	EnregistrerActionsClesUtilisateur(Catalogue)
	EnregistrerActionsSuppressionUtilisateur(Catalogue)
	EnregistrerActionsMFA(Catalogue)
	EnregistrerActionsGroupe(Catalogue)
	EnregistrerActionsClient(Catalogue)
	EnregistrerActionsPermission(Catalogue)
	EnregistrerActionsGrammairePermission(Catalogue)
	EnregistrerActionsLecture(Catalogue)
	EnregistrerActionsLectureSuite(Catalogue)
	EnregistrerActionsGPO(Catalogue)
	EnregistrerActionsLectureEtat(Catalogue)
	EnregistrerActionsServeur(Catalogue)
	EnregistrerActionsConformiteGPO(Catalogue)
	EnregistrerActionsArborescence(Catalogue)
	EnregistrerActionsReglages(Catalogue)
	EnregistrerActionsCertificat(Catalogue)
	EnregistrerActionsEnrolement(Catalogue)
	EnregistrerActionsDNS(Catalogue)
	EnregistrerActionsPolitiqueMotDePasse(Catalogue)
}

// Executer applique une action du registre partagé.
func Executer(nom string, a Appelant, p Params) (Resultat, error) {
	return Defaut.Executer(nom, a, p)
}
