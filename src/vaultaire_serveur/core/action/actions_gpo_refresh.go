package action

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"vaultaire/core/database"
	dbgpo "vaultaire/core/database/db_gpo"
	"vaultaire/core/gpo"
	gpomanager "vaultaire/ducky-network/gpo_manager"
)

// Déclenchement d'un cycle GPO hors du tour périodique.
//
// # Pourquoi le droit porte sur la MACHINE et non sur la GPO
//
// L'action ne modifie aucune politique : elle demande à un poste de réappliquer
// celle qu'il aurait reçue de toute façon. Ce qu'elle engage, c'est donc la
// machine — son processeur, ses services redémarrés par les modules, sa
// disponibilité pendant le cycle.
//
// Exiger `write:update:gpo` aurait donné à quiconque peut éditer une GPO le
// pouvoir de lancer un cycle sur N'IMPORTE QUEL poste du parc, y compris hors
// de sa délégation. `write:update:client` sur les domaines de la machine dit
// exactement ce qui se passe : j'agis sur cette machine-là.
//
// # Sur TOUS les domaines de la machine (TO-DO 150)
//
// L'action déclarait UnDomaineSuffit : le droit sur un seul des domaines de la
// machine ouvrait le geste. C'était la seule écriture du catalogue dans ce cas,
// avec `cluster.refresh_nodes` — et la suite `--test` le signalait depuis
// toujours, sans que personne ne la lance. Un poste rangé à la fois dans paris
// et dans lyon se faisait relancer par le délégué de paris seul ; or ce qu'un
// cycle engage — des services redémarrés, un poste occupé — touche aussi lyon.
//
// La règle du registre n'a pas d'exception : une écriture exige le droit sur
// tous les domaines de sa cible. Ce délégué ne pouvait déjà ni modifier ni
// retirer ce poste ; il ne le fait plus rafraîchir non plus, et la boucle le
// compte parmi les machines hors de son périmètre.
//
// # Pourquoi il n'y a pas d'action « tout le parc »
//
// Une action unique qui rafraîchirait tout ne pourrait porter qu'un droit
// global, et le délégué qui administre dix postes n'aurait rien. La ligne de
// commande fait donc la boucle et appelle cette action une fois par machine :
// chaque poste est contrôlé pour lui-même, et un parc mixte donne un résultat
// partiel qui s'annonce comme tel.

//
// # Trois façons de la demander, une seule boucle (TO-DO 169)
//
// Une machine, tout le parc connecté, ou les machines d'une GPO : la ligne de
// commande faisait la boucle elle-même, et le portail ne proposait rien — alors
// que c'est là qu'on modifie un module, et là qu'on attend ensuite de le voir
// appliqué. La boucle vit maintenant ICI (RafraichirMachines), et les deux
// façades l'empruntent : un bouton et une commande qui ne compteraient pas
// pareil ce qu'ils ont joint finiraient par ne plus dire la même chose.

// EnregistrerActionsRafraichissementGPO ajoute le déclenchement de cycle.
func EnregistrerActionsRafraichissementGPO(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:      "gpo.refresh",
		CleRBAC:  "write:update:client",
		Portee:   PorteeClient,
		Resume:   "demande à une machine de rafraîchir sa politique maintenant",
		Executer: rafraichirMachine,
	})
}

// IssueCycle est ce que rend `gpo.refresh` dans Resultat.Donnees.
type IssueCycle struct {
	// Remise : la trame est partie — par ce core, ou par un autre du cluster
	// quand la demande a été suivie jusqu'au bout.
	Remise bool
	// Relayee : la machine n'est pas connectée ici, et la demande a été écrite
	// en base pour les autres cores (TO-DO 172).
	Relayee bool
	// Demande : la ligne écrite, quand elle l'a été.
	Demande int64
	// Par : le core qui l'a remise, quand ce n'est pas celui-ci.
	Par string
}

// AttenteDuRelais borne le temps qu'on attend qu'un autre core prenne une
// demande relayée : ils la relèvent toutes les deux secondes.
var AttenteDuRelais = 4 * time.Second

// Le relais par la base, remplaçable par les tests (il faut une base et un
// cluster).
var (
	autresCores = func() int {
		n, err := dbgpo.AutresCoresEnLigne(database.GetDatabase(), gpomanager.NomDuCoreLocal())
		if err != nil {
			return 0
		}
		return n
	}
	ecrireDemande = func(id, motif string) (int64, error) {
		return dbgpo.EcrireDemandeDeCycle(database.GetDatabase(), id, motif, gpomanager.NomDuCoreLocal())
	}
	issuesDes = func(ids []int64) (map[int64]dbgpo.IssueDeDemande, error) {
		return dbgpo.IssuesDesDemandes(database.GetDatabase(), ids)
	}
	dormir = time.Sleep
)

// attendreLesIssues relit les demandes relayées jusqu'à ce qu'elles soient
// toutes prises, ou que AttenteDuRelais soit passée.
func attendreLesIssues(ids []int64) map[int64]dbgpo.IssueDeDemande {
	echeance := time.Now().Add(AttenteDuRelais)
	issues := map[int64]dbgpo.IssueDeDemande{}
	for {
		lues, err := issuesDes(ids)
		if err == nil {
			issues = lues
			toutes := true
			for _, id := range ids {
				if !issues[id].Prise {
					toutes = false
					break
				}
			}
			if toutes {
				return issues
			}
		}
		if !time.Now().Before(echeance) {
			return issues
		}
		dormir(200 * time.Millisecond)
	}
}

// rafraichirMachine pousse 05_18 à une machine.
//
// Une machine hors ligne n'est PAS une erreur : elle fera un cycle en
// revenant. Rendre une erreur aurait fait échouer un rafraîchissement de parc
// à cause d'un portable fermé, et poussé à ignorer les erreurs de cette action
// — donc aussi les vraies.
//
// # Sur un cluster (TO-DO 172)
//
// Une machine absente d'ici est peut-être connectée à un autre core. La demande
// est alors écrite en base, et le core qui tient la machine la remet (voir
// gpo_manager/relais_cycle.go). Sauf `attendre` = « non » — la boucle de
// RafraichirMachines attend une seule fois pour tout le parc —, l'action
// attend l'issue et la dit.
func rafraichirMachine(a Appelant, p Params) (Resultat, error) {
	id := strings.TrimSpace(p.Get("computeur_id"))
	if id == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	motif := strings.TrimSpace(p.Get("motif"))
	if motif == "" {
		motif = "demande de " + a.Username
	}

	remis, err := pousserIci(id, motif)
	if err != nil {
		// Connectée, mais la trame n'est pas partie. Ce n'est PAS « hors
		// ligne » : le dire ferait attendre une reconnexion qui n'aura pas
		// lieu, puisque la machine est déjà là (TO-DO 89).
		return Resultat{
			Message: fmt.Sprintf("Machine %s connectée, mais la demande n'a pas pu lui être remise (%v). "+
				"Réessayez ; à défaut, elle rafraîchira sa politique à son prochain tour.", id, err),
			Donnees: IssueCycle{},
		}, nil
	}
	if remis {
		return Resultat{
			Message: fmt.Sprintf("Rafraîchissement demandé à %s.", id),
			Donnees: IssueCycle{Remise: true},
		}, nil
	}

	// Pas connectée ICI. Seule sur ce core : hors ligne, comme avant.
	if autresCores() == 0 {
		return Resultat{
			Message: fmt.Sprintf("Machine %s hors ligne : elle rafraîchira sa politique à sa reconnexion.", id),
			Donnees: IssueCycle{},
		}, nil
	}
	demande, errD := ecrireDemande(id, motif)
	if errD != nil {
		return Resultat{
			Message: fmt.Sprintf("Machine %s non connectée à ce core, et la demande n'a pas pu être relayée "+
				"aux autres (%v) : elle rafraîchira sa politique à sa reconnexion, ou à son tour.", id, errD),
			Donnees: IssueCycle{},
		}, nil
	}
	issue := IssueCycle{Relayee: true, Demande: demande}
	if strings.TrimSpace(p.Get("attendre")) == "non" {
		return Resultat{
			Message: fmt.Sprintf("Machine %s non connectée à ce core : demande relayée aux autres cores.", id),
			Donnees: issue,
		}, nil
	}
	lue := attendreLesIssues([]int64{demande})[demande]
	switch {
	case lue.Prise && lue.Remise:
		issue.Remise, issue.Par = true, lue.PrisePar
		return Resultat{Message: fmt.Sprintf("Rafraîchissement demandé à %s, par le core %s qui la tient.",
			id, lue.PrisePar), Donnees: issue}, nil
	case lue.Prise:
		issue.Par = lue.PrisePar
		return Resultat{Message: fmt.Sprintf("Machine %s connectée au core %s, mais la demande n'a pas pu lui "+
			"être remise : elle rafraîchira sa politique à son prochain tour.", id, lue.PrisePar), Donnees: issue}, nil
	}
	return Resultat{
		Message: fmt.Sprintf("Machine %s connectée à aucun core du cluster : elle rafraîchira sa politique "+
			"à sa reconnexion.", id),
		Donnees: issue,
	}, nil
}

// pousserIci est remplaçable par les tests : la poussée demande un tunnel.
var pousserIci = gpomanager.DemanderRafraichissement

// BilanRafraichissement compte ce qu'une demande de cycle faite à plusieurs
// machines a donné.
type BilanRafraichissement struct {
	// Visees : machines à qui la demande devait être faite.
	Visees int
	// Jointes : la trame est partie.
	Jointes int
	// NonJointes : hors ligne, ou connectée sans que la trame ait pu partir.
	// Elles rafraîchiront à leur reconnexion, ou à leur tour.
	NonJointes int
	// JointesAilleurs : parmi les Jointes, celles qu'un AUTRE core du cluster
	// a jointes, par une demande relayée en base (TO-DO 172).
	JointesAilleurs int
	// Relayees : demandes écrites pour les autres cores. Dit que le bilan a
	// regardé tout le cluster, et pas seulement ce core.
	Relayees int
	// Refusees : hors du périmètre de l'appelant, ou inconnues de l'annuaire.
	Refusees int
}

// RafraichirMachines demande un cycle à chaque machine donnée, par l'action
// `gpo.refresh` — donc avec SON contrôle de droits, machine par machine.
//
// Les machines refusées sont comptées, pas nommées : lister celles qu'on n'a
// pas le droit de toucher renseignerait sur un parc qu'on n'a pas le droit de
// voir.
func RafraichirMachines(a Appelant, ids []string, motif string) BilanRafraichissement {
	bilan := BilanRafraichissement{Visees: len(ids)}
	var relayees []int64
	for _, id := range ids {
		// « attendre = non » : l'attente des demandes relayées se fait UNE fois,
		// pour tout le parc, après la boucle. Machine par machine, un parc de
		// cent postes sur un autre core attendrait cent fois.
		res, err := executerLeRafraichissement(a, Params{"computeur_id": id, "motif": motif, "attendre": "non"})
		if err != nil {
			bilan.Refusees++
			continue
		}
		issue, _ := res.Donnees.(IssueCycle)
		switch {
		case issue.Remise:
			bilan.Jointes++
		case issue.Relayee:
			relayees = append(relayees, issue.Demande)
		default:
			bilan.NonJointes++
		}
	}
	if len(relayees) > 0 {
		bilan.Relayees = len(relayees)
		lues := attendreLesIssues(relayees)
		for _, d := range relayees {
			if l := lues[d]; l.Prise && l.Remise {
				bilan.Jointes++
				bilan.JointesAilleurs++
			} else {
				bilan.NonJointes++
			}
		}
	}
	return bilan
}

// executerLeRafraichissement est remplaçable par les tests : l'action pousse
// une trame à une session, ce qui demande un core.
var executerLeRafraichissement = func(a Appelant, p Params) (Resultat, error) {
	return Executer("gpo.refresh", a, p)
}

// lireLaGPO et machinesDeLaGPO sont remplaçables par les tests : les deux
// lisent la base.
var (
	lireLaGPO = func(a Appelant, nom string) (*gpo.Policy, error) {
		// Par l'action de lecture : le droit de LIRE cette GPO est exigé avant
		// d'en énumérer les machines.
		res, err := Executer("gpo.get", a, Params{"gpo": nom})
		if err != nil {
			return nil, err
		}
		policy, ok := res.Donnees.(*gpo.Policy)
		if !ok || policy == nil {
			return nil, fmt.Errorf("GPO %q introuvable", nom)
		}
		return policy, nil
	}
	machinesDeLaGPO = func(policyID int) ([]string, error) {
		return dbgpo.MachinesLieesA(database.GetDatabase(), policyID)
	}
)

// ErrGPODeCompte : on a demandé un cycle pour une GPO de portée utilisateur.
var ErrGPODeCompte = errors.New("une GPO de compte s'applique à l'ouverture de session de chaque compte : " +
	"il n'y a pas de cycle à demander, et une session déjà ouverte ne change pas")

// RafraichirMachinesDeLaGPO demande un cycle aux machines liées à une GPO.
//
// # Ce qu'elle refuse
//
// Une GPO de COMPTE. Sa politique n'est pas appliquée par le cycle d'une
// machine mais à l'ouverture de session de chaque personne : demander un cycle
// ferait travailler tous les postes pour rien, et laisserait croire que la
// modification est partie. On le dit, au lieu de le faire.
func RafraichirMachinesDeLaGPO(a Appelant, nom string) (BilanRafraichissement, error) {
	nom = strings.TrimSpace(nom)
	if nom == "" {
		return BilanRafraichissement{}, fmt.Errorf("nom de GPO requis")
	}
	policy, err := lireLaGPO(a, nom)
	if err != nil {
		return BilanRafraichissement{}, err
	}
	if policy.Scope == gpo.ScopeUser {
		return BilanRafraichissement{}, ErrGPODeCompte
	}
	ids, err := machinesDeLaGPO(policy.ID)
	if err != nil {
		return BilanRafraichissement{}, err
	}
	return RafraichirMachines(a, ids, "GPO "+nom+", demande de "+a.Username), nil
}

// Lisible dit le bilan en clair. « quoi » nomme ce qui était visé : « liée(s) à
// la GPO base », « connectée(s) ».
func (b BilanRafraichissement) Lisible(quoi string) string {
	if b.Visees == 0 {
		return "Aucune machine " + quoi + " : il n'y a personne à qui demander un cycle."
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "Cycle demandé à %d machine(s) sur %d %s", b.Jointes, b.Visees, quoi)
	if b.JointesAilleurs > 0 {
		fmt.Fprintf(&sb, ", dont %d par un autre core du cluster", b.JointesAilleurs)
	}
	sb.WriteString(".")
	if b.NonJointes > 0 {
		// « sur tout le cluster » seulement si les autres cores ont été
		// interrogés : sans relais, une machine absente d'ici est simplement
		// hors ligne — il n'y a pas d'autre core.
		ou := ""
		if b.Relayees > 0 {
			ou = " (sur aucun core du cluster)"
		}
		fmt.Fprintf(&sb, " %d hors ligne%s ou non jointe(s) : elles rafraîchiront à leur reconnexion, ou à leur tour.", b.NonJointes, ou)
	}
	if b.Refusees > 0 {
		fmt.Fprintf(&sb, " %d hors de votre périmètre n'ont pas été touchées.", b.Refusees)
	}
	return sb.String()
}
