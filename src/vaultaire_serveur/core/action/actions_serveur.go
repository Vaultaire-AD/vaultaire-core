package action

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/database"
	dbcertificates "vaultaire/core/database/db_certificates"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	hosthandler "vaultaire/ducky-network/host_handler"
)

// Actions sur le SERVEUR lui-même : cluster et certificats.
//
// # Pourquoi ces objets ont enfin leurs propres droits
//
// Ni un nœud de cluster ni un certificat TLS n'appartient à un domaine de
// l'annuaire. Faute de clé qui leur corresponde, les commandes empruntaient
// celles des machines :
//
//	cluster list          read:get:client sur « * »
//	cluster purge-delay   write:update:client sur « * »
//	certificate list      read:get:client sur « * »
//	certificate regenerate write:create:client sur « * »
//
// Deux conséquences, opposées et également gênantes.
//
// TROP LARGE : régénérer le certificat LDAPS change l'empreinte que tout le
// parc a importée dans son magasin de confiance — les clients cessent de se
// connecter jusqu'à réimport. Confier cela à quiconque peut créer une machine
// est disproportionné.
//
// TROP ÉTROIT : lire le certificat PUBLIC, ou consulter l'état du cluster,
// exigeait le droit de lire toutes les machines de tous les domaines. Une
// équipe d'astreinte à qui l'on veut donner la vue du cluster recevait avec
// elle l'annuaire des postes.
//
// Les quatre clés sont des ACTIONS SPÉCIALES et non des objets RBAC : voir
// permission.ActionReadCluster pour le raisonnement.
//
// # Fail-closed assumé
//
// Ces clés ne sont accordées à personne tant qu'on ne les accorde pas. Après
// mise à jour, `vlt cluster` et `vlt certificate list` répondent « permission
// refusée » en nommant la clé manquante, jusqu'à ce qu'elle soit donnée. C'est
// le choix qui laisse la trace la plus claire — un droit qu'on croyait avoir
// et qui n'y est pas se voit immédiatement, là où une migration automatique
// aurait accordé des droits sans que personne les ait demandés.

// EnregistrerActionsServeur ajoute cluster et certificats.
func EnregistrerActionsServeur(r *Registre) {
	// --- cluster ---

	r.MustEnregistrer(Definition{
		Nom:     "cluster.list_nodes",
		CleRBAC: permission.ActionReadCluster,
		Portee:  PorteeGlobale,
		// UnDomaineSuffit est déclaré bien qu'il ne change RIEN ici.
		//
		// La portée est « * » et rien d'autre : sur une liste d'un seul
		// élément, « tous les domaines » et « au moins un » donnent le même
		// verdict. Le drapeau est donc inerte.
		//
		// Il est posé quand même parce que l'invariant qui le vérifie — toute
		// lecture le déclare, aucune écriture ne le déclare — vaut mieux net
		// que nuancé. Une règle sans exception se relit sans réfléchir ; une
		// règle avec « sauf les objets sans domaine » demande de savoir
		// lesquels, et se contourne le jour où l'on se trompe de catégorie.
		FiltreInutile: "un nœud de cluster n'appartient à aucun domaine ; il n'y a " +
			"pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les nœuds du cluster",
		Executer: listerNoeuds,
	})

	r.MustEnregistrer(Definition{
		Nom:             "cluster.get_purge_delay",
		CleRBAC:         permission.ActionReadCluster,
		Portee:          PorteeGlobale,
		Resume:          "lit le délai avant suppression d'un service parti",
		Executer: func(_ Appelant, _ Params) (Resultat, error) {
			return lireDelaiDePurge()
		},
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.set_purge_delay",
		// Clé d'ÉCRITURE distincte : allonger le délai laisse traîner des
		// identités, le raccourcir en détruit plus vite. C'est une décision qui
		// engage le parc, pas une consultation.
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "règle le délai avant suppression d'un service parti",
		Executer: reglerDelaiDePurge,
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.set_node_exposure",
		// Même clé d'écriture que les autres réglages du cluster.
		//
		// Elle en vaut la peine : l'adresse déclarée ici est distribuée à TOUT
		// le parc par la trame 04_04, et chaque agent l'ajoute à sa liste de
		// serveurs joignables. Pointer un nœud vers une adresse qu'on contrôle
		// ne suffit pas à détourner une authentification — l'empreinte de clé
		// reste vérifiée, et elle n'est pas modifiable ici — mais suffit
		// largement à couper le parc.
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "déclare par où les agents joignent un nœud, sa priorité et son exposition",
		Executer: reglerExpositionNoeud,
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.client_targets",
		// LECTURE, donc read:cluster : la vue décrit les nœuds, pas la machine.
		//
		// On aurait pu exiger read:get:client, puisqu'on désigne une machine.
		// Ce serait le mauvais critère : ce qui est révélé ici est la topologie
		// du cluster — quels nœuds existent, lesquels servent quels sites — et
		// non l'inventaire de la machine. Le nom du client ne fait que choisir
		// le point de vue.
		CleRBAC: permission.ActionReadCluster,
		Portee:  PorteeGlobale,
		FiltreInutile: "la réponse décrit les nœuds du cluster, qui n'appartiennent " +
			"à aucun domaine ; il n'y a pas de périmètre selon lequel la réduire",
		UnDomaineSuffit: true,
		Resume:          "liste, dans l'ordre, les nœuds qu'une machine joindra",
		Executer:        ciblesDuClient,
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.set_node_groups",
		// write:cluster, comme les autres décisions sur un nœud.
		//
		// L'affinité ne donne AUCUN droit — elle décide d'un rang dans une
		// liste. Elle mérite quand même une clé d'écriture : rattacher tous les
		// proxies à un groupe vide reviendrait à défaire la répartition d'un
		// parc entier sans qu'aucune erreur ne soit levée nulle part.
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "fixe les groupes qu'un nœud sert en priorité",
		Executer: reglerGroupesDuNoeud,
	})

	r.MustEnregistrer(Definition{
		Nom:     "cluster.get_metrics_retention",
		CleRBAC: permission.ActionReadCluster,
		Portee:  PorteeGlobale,
		Resume:  "lit la durée de conservation des métriques de nœuds",
		Executer: func(_ Appelant, _ Params) (Resultat, error) {
			return lireRetentionMetriques()
		},
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.set_metrics_retention",
		// Même clé d'écriture que le délai de purge, et pour la même raison :
		// raccourcir la rétention DÉTRUIT des données au prochain passage. Ce
		// n'est pas une consultation.
		CleRBAC:  permission.ActionWriteCluster,
		Portee:   PorteeGlobale,
		Resume:   "règle la durée de conservation des métriques de nœuds",
		Executer: reglerRetentionMetriques,
	})

	// --- certificats ---

	r.MustEnregistrer(Definition{
		Nom:             "certificate.list",
		CleRBAC:         permission.ActionReadCertificate,
		Portee:          PorteeGlobale,
		FiltreInutile: "un certificat TLS n'appartient à aucun domaine ; il n'y a " +
			"pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les certificats du serveur",
		Executer: listerCertificats,
	})

	r.MustEnregistrer(Definition{
		Nom:             "certificate.get",
		CleRBAC:         permission.ActionReadCertificate,
		Portee:          PorteeGlobale,
		Resume:          "affiche un certificat public et son audit",
		Executer:        ficheCertificatParNom,
	})

	r.MustEnregistrer(Definition{
		Nom:     "certificate.regenerate",
		CleRBAC: permission.ActionWriteCertificate,
		Portee:  PorteeGlobale,
		Resume:  "régénère le certificat TLS du serveur",
		// L'exécution reste dans commandcertificate : elle génère une paire de
		// clés, la remplace en base et rend un compte rendu détaillé. La
		// déplacer ici demanderait d'y porter la génération de certificat —
		// un chantier qui n'a rien à voir avec le contrôle d'accès.
		//
		// L'action existe donc pour porter la CLÉ et la PORTÉE, et son
		// exécution est déléguée. C'est le seul cas du catalogue, et il est
		// nommé pour qu'on le retrouve.
		Executer: regenererCertificat,
	})
}

// RegenererCertificat est branchée au démarrage par le paquet qui sait le
// faire.
//
// # Pourquoi une indirection plutôt qu'un appel direct
//
// La régénération vit dans commandcertificate, qui importe déjà le registre :
// un appel direct créerait un cycle d'imports. L'inversion est la même que
// pour permission.SetRevokedChecker, et pour la même raison.
//
// Nil tant que personne ne l'a branchée : l'action refuse alors plutôt que de
// rendre un succès silencieux. Un serveur mal câblé doit le dire.
var RegenererCertificat func(a Appelant, p Params) (string, error)

func regenererCertificat(a Appelant, p Params) (Resultat, error) {
	if RegenererCertificat == nil {
		return Resultat{}, fmt.Errorf(
			"régénération non branchée : action.RegenererCertificat est nil, " +
				"le serveur a démarré sans raccorder commandcertificate")
	}
	msg, err := RegenererCertificat(a, p)
	if err != nil {
		return Resultat{}, err
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a régénéré un certificat TLS du serveur", a.Username))
	return Resultat{Message: msg}, nil
}

// --- cluster -----------------------------------------------------------------

// NoeudsCluster porte les nœuds et, éventuellement, le rôle demandé.
type NoeudsCluster struct {
	Role   string
	Noeuds []clusterstorage.Node
}

func listerNoeuds(_ Appelant, p Params) (Resultat, error) {
	db := database.GetDatabase()
	role := strings.ToLower(p.Get("role"))

	var noeuds []clusterstorage.Node
	var err error
	if role != "" {
		noeuds, err = clusterdatabase.GetActiveNodesByRole(db, role)
	} else {
		noeuds, err = clusterdatabase.GetAllNodes(db)
	}
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des nœuds du cluster : %w", err)
	}

	// Les groupes affins sont renseignés pour l'AFFICHAGE seulement.
	//
	// Le champ Affin, lui, reste faux : cette liste n'a pas de demandeur, et
	// « affin ? » n'a pas de réponse hors d'une demande. Ce qu'on montre ici est
	// « quels groupes ce nœud sert », pas « ce nœud me sert-il ».
	//
	// Un échec de lecture n'interrompt pas la liste : une colonne vide vaut
	// mieux qu'un refus d'afficher l'état du cluster.
	for i := range noeuds {
		groupes, errG := clusterdatabase.NomsDesGroupesDuNoeud(db, noeuds[i].ID)
		if errG != nil {
			logs.Write_Log("WARNING",
				"cluster: affinités du nœud "+noeuds[i].Hostname+" illisibles : "+errG.Error())
			continue
		}
		noeuds[i].GroupesAffins = groupes
	}

	message := fmt.Sprintf("%d nœud(s).", len(noeuds))
	if role != "" {
		message = fmt.Sprintf("%d nœud(s) actif(s) pour le rôle %s.", len(noeuds), role)
	}
	return Resultat{Message: message, Donnees: NoeudsCluster{Role: role, Noeuds: noeuds}}, nil
}

// reglerExpositionNoeud déclare par où les agents joignent un nœud.
//
// # Le problème auquel cette action répond
//
// `ip_address` est ce que le nœud voit de LUI-MÊME. Derrière une redirection
// NAT, dans un conteneur, ou sur un hôte à plusieurs interfaces, ce n'est pas
// l'adresse par laquelle le parc l'atteint — et le nœud n'a aucun moyen de le
// savoir, puisqu'il ne voit pas son infrastructure de l'extérieur.
//
// Il annonçait donc une adresse privée, que la trame 04_04 distribuait à tout
// le parc, et que personne ne pouvait joindre.
//
// # Mise à jour partielle
//
// Un champ ABSENT n'est pas touché ; un champ présent et VIDE efface la
// déclaration. La distinction est ce qui permet à `vlt cluster priority` de ne
// pas remettre en rotation un nœud sorti pour maintenance, tout en laissant le
// formulaire web envoyer les quatre champs d'un coup.
func reglerExpositionNoeud(a Appelant, p Params) (Resultat, error) {
	hostname := p.Get("node")
	if hostname == "" {
		hostname = p.Get("hostname")
	}
	if hostname == "" {
		return Resultat{}, fmt.Errorf("nom du nœud requis")
	}

	db := database.GetDatabase()
	avant, err := clusterdatabase.NoeudParHostname(db, hostname)
	if err != nil {
		return Resultat{}, err
	}

	var champs clusterdatabase.ExpositionNoeud

	if p.Presente("address") {
		adresse, err := clusterstorage.ValiderAdressePublique(p.Get("address"))
		if err != nil {
			return Resultat{}, err
		}
		champs.AdressePublique = &adresse
	}
	if p.Presente("port") {
		port, err := clusterstorage.ValiderPortPublic(p.Get("port"))
		if err != nil {
			return Resultat{}, err
		}
		champs.PortPublic = &port
	}
	if p.Presente("priority") {
		brut := p.Get("priority")
		priorite := 0
		if brut != "" {
			priorite, err = strconv.Atoi(brut)
			if err != nil {
				return Resultat{}, fmt.Errorf("priorité invalide : %q n'est pas un nombre", brut)
			}
		}
		champs.Priorite = &priorite
	}
	if p.Presente("exposed") {
		// Présent vaut décision explicite, absent vaut « n'y touche pas ».
		//
		// C'est pourquoi le formulaire web emploie une LISTE et non une case à
		// cocher : une case décochée n'est pas envoyée par le navigateur, donc
		// elle se lirait ici comme « ne rien changer », et retirer un nœud de la
		// rotation depuis le web serait impossible.
		expose := estVrai(p.Get("exposed"))
		champs.ExposeAuxAgents = &expose
	}

	if champs.Vide() {
		return Resultat{}, fmt.Errorf(
			"rien à modifier : indiquez une adresse, un port, une priorité ou une exposition")
	}

	if err := clusterdatabase.MettreAJourExposition(db, hostname, champs); err != nil {
		return Resultat{}, err
	}

	apres, err := clusterdatabase.NoeudParHostname(db, hostname)
	if err != nil {
		return Resultat{Message: "Nœud " + hostname + " mis à jour."}, nil
	}

	// Trace SECURITY, et l'état AVANT y figure.
	//
	// « le nœud vaut X » ne dit pas ce qui a changé ; six mois plus tard, quand
	// une partie du parc n'arrive plus à s'authentifier, c'est l'écart qu'on
	// cherche. L'adresse d'un nœud est distribuée à toutes les machines : la
	// modifier a la portée d'un changement d'infrastructure, pas d'un réglage
	// d'affichage.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a modifié l'exposition du nœud %s : accès %s → %s, priorité %d → %d, exposé %t → %t",
		a.Username, hostname,
		descriptionAcces(avant), descriptionAcces(apres),
		avant.Priorite, apres.Priorite,
		avant.ExposeAuxAgents, apres.ExposeAuxAgents))

	return Resultat{Message: messageExposition(apres), Donnees: apres}, nil
}

// CiblesClient porte la réponse de cluster.client_targets.
type CiblesClient struct {
	ComputeurID string
	Cibles      []clusterdatabase.CibleClient
	// GroupesClient sert à expliquer une liste sans aucun nœud affin : la cause
	// ordinaire n'est pas que les affinités ne marchent pas, c'est que la
	// machine n'est dans aucun groupe.
	GroupesClient []int
	// Ecartes liste les nœuds qu'AUCUN agent ne reçoit, et pourquoi. Un nœud
	// absent ne laisse aucune trace côté agent : quand un proxy fraîchement
	// déployé ne sert personne, la question n'est pas « dans quel ordre » mais
	// « pourquoi pas du tout ».
	Ecartes []string
}

// ciblesDuClient rend, dans l'ordre, les nœuds qu'une machine joindra.
//
// La liste n'est pas recalculée pour l'occasion : c'est la MÊME fonction que
// celle qui répond à la trame 04_04. Une seconde implémentation finirait par
// diverger, et la vue affirmerait un ordre que le parc ne suit pas — pire que
// pas de vue du tout, puisqu'on cesserait de chercher ailleurs.
func ciblesDuClient(_ Appelant, p Params) (Resultat, error) {
	computeurID := p.Get("computeur_id")
	if computeurID == "" {
		computeurID = p.Get("client")
	}
	if computeurID == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	db := database.GetDatabase()
	cibles, groupes, err := clusterdatabase.CiblesDuClient(db, computeurID)
	if err != nil {
		return Resultat{}, err
	}

	// Les écartés sont une aide au diagnostic : leur lecture ne doit pas faire
	// échouer la réponse principale.
	ecartes, errE := clusterdatabase.NoeudsEcartes(db)
	if errE != nil {
		logs.Write_Log("WARNING", "cluster: nœuds écartés illisibles : "+errE.Error())
	}

	message := fmt.Sprintf("%d nœud(s) joignable(s) pour %s, dans l'ordre.", len(cibles), computeurID)
	if len(cibles) == 0 {
		message = "Aucun nœud joignable pour " + computeurID +
			" : cette machine ne peut s'authentifier que par ses serveurs statiques."
	}

	return Resultat{
		Message: message,
		Donnees: CiblesClient{
			ComputeurID:   computeurID,
			Cibles:        cibles,
			GroupesClient: groupes,
			Ecartes:       ecartes,
		},
	}, nil
}

// reglerGroupesDuNoeud fixe les groupes qu'un nœud sert en priorité.
//
// # Ce que l'affinité fait, et ce qu'elle ne fait pas
//
// Un agent membre d'un groupe affin à un nœud reçoit ce nœud AVANT les autres de
// même rôle. C'est une préférence, jamais une exclusivité : tous les nœuds
// exposés restent dans sa liste, en queue. Sans cette règle, la panne du proxy
// d'un site deviendrait une panne d'authentification pour ce site.
//
// # Remplacement, et non ajout
//
// Le paramètre décrit l'état voulu. Une liste vide retire toutes les affinités —
// c'est le geste qui remet un nœud au service de tout le monde, et il doit
// exister.
func reglerGroupesDuNoeud(a Appelant, p Params) (Resultat, error) {
	hostname := p.Get("node")
	if hostname == "" {
		return Resultat{}, fmt.Errorf("nom du nœud requis")
	}
	if !p.Presente("groups") {
		return Resultat{}, fmt.Errorf(
			"groupes requis : donnez la liste voulue, ou une liste vide pour " +
				"que ce nœud serve tout le parc sans préférence")
	}

	db := database.GetDatabase()
	noeud, err := clusterdatabase.NoeudParHostname(db, hostname)
	if err != nil {
		return Resultat{}, err
	}

	noms := champsSepares(p.Get("groups"))
	ids, introuvables, err := clusterdatabase.IDsDeGroupesParNoms(db, noms)
	if err != nil {
		return Resultat{}, err
	}

	// Réglage MANUEL : un groupe inconnu est refusé.
	//
	// C'est l'inverse du choix fait pour une clé d'enrôlement, et les deux sont
	// justes. Ici quelqu'un tape un nom : accepter silencieusement une faute de
	// frappe poserait une préférence qui n'existe pas, et on chercherait plus
	// tard pourquoi le site n'est pas servi. Une clé d'enrôlement, elle, sert
	// des mois après son émission, et un groupe renommé entre-temps ne doit pas
	// bloquer un déploiement.
	if len(introuvables) > 0 {
		return Resultat{}, fmt.Errorf("groupe(s) inconnu(s) : %s",
			strings.Join(introuvables, ", "))
	}

	avant, _ := clusterdatabase.NomsDesGroupesDuNoeud(db, noeud.ID)

	if err := clusterdatabase.RemplacerGroupesDuNoeud(db, noeud.ID, ids); err != nil {
		return Resultat{}, err
	}

	apres, err := clusterdatabase.NomsDesGroupesDuNoeud(db, noeud.ID)
	if err != nil {
		apres = noms
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé l'affinité du nœud %s : %s → %s",
		a.Username, noeud.Hostname, listeLisible(avant), listeLisible(apres)))

	return Resultat{Message: messageAffinite(noeud.Hostname, noeud.Role, apres), Donnees: apres}, nil
}

// champsSepares découpe une saisie « a,b c » en éléments.
//
// Virgule ET espace : le formulaire web envoie une sélection jointe par des
// virgules, la ligne de commande reçoit des arguments séparés par des espaces.
// Accepter les deux évite d'imposer une syntaxe au mauvais endroit.
func champsSepares(brut string) []string {
	remplacé := strings.ReplaceAll(brut, ",", " ")
	return strings.Fields(remplacé)
}

// listeLisible rend une liste de noms, ou « aucun » si elle est vide.
//
// « affinité de proxy1 :  →  » ne se lit pas. Le journal doit rester
// compréhensible six mois plus tard, quand on cherche qui a défait quoi.
func listeLisible(noms []string) string {
	if len(noms) == 0 {
		return "aucun"
	}
	return strings.Join(noms, ", ")
}

// messageAffinite dit ce que le réglage change réellement pour les agents.
func messageAffinite(hostname, role string, groupes []string) string {
	if len(groupes) == 0 {
		return fmt.Sprintf(
			"Le nœud %s n'a plus d'affinité : il est servi à tout le parc "+
				"selon son rôle et sa priorité, sans préférence de site.", hostname)
	}
	return fmt.Sprintf(
		"Le nœud %s (%s) sert en priorité : %s. Les agents de ces groupes le "+
			"recevront avant les autres %s ; les autres nœuds restent dans leur "+
			"liste, en queue.",
		hostname, role, strings.Join(groupes, ", "), pluriel(role))
}

// pluriel rend le rôle au pluriel pour la phrase ci-dessus.
func pluriel(role string) string {
	if role == "proxy" {
		return "proxies"
	}
	return role + "s"
}

// descriptionAcces rend l'accès d'un nœud sous une forme comparable.
func descriptionAcces(n clusterstorage.Node) string {
	acces := clusterstorage.AdresseAffichee(n.AdresseEffective(), n.PortEffectif())
	if acces == "" {
		acces = "aucun"
	}
	if n.ExpositionDeclaree() {
		return acces + " (déclaré)"
	}
	return acces + " (vu par le nœud)"
}

// messageExposition dit ce que les agents recevront désormais.
//
// Répéter l'adresse effective plutôt que « mise à jour » : c'est la seule façon
// de voir tout de suite qu'on a effacé une déclaration et qu'on est retombé sur
// l'adresse interne du nœud, qui est l'erreur que cette action existe pour
// corriger.
func messageExposition(n clusterstorage.Node) string {
	acces := clusterstorage.AdresseAffichee(n.AdresseEffective(), n.PortEffectif())

	var quoi string
	if n.ExpositionDeclaree() {
		quoi = fmt.Sprintf("Les agents joindront %s à %s (adresse déclarée).", n.Hostname, acces)
	} else {
		quoi = fmt.Sprintf(
			"Aucune adresse déclarée pour %s : les agents recevront %s, "+
				"c'est-à-dire ce que le nœud voit de lui-même.", n.Hostname, acces)
	}

	if !n.ExposeAuxAgents {
		return quoi + " Le nœud est HORS ROTATION : il n'est annoncé à aucun agent " +
			"tant qu'il n'y est pas remis."
	}
	return quoi
}

// DelaiDePurge porte la valeur courante.
//
// Une structure plutôt qu'une time.Duration nue : zéro signifie « purge
// désactivée » et non « immédiate », et un type dédié force l'appelant à lire
// ce commentaire plutôt qu'à formater une durée qu'il croit comprendre.
type DelaiDePurge struct {
	Delai time.Duration

	// Desactivee distingue explicitement les deux sens de zéro.
	Desactivee bool
}

func lireDelaiDePurge() (Resultat, error) {
	d := hosthandler.PurgeDelay(database.GetDatabase())
	if d <= 0 {
		return Resultat{
			Message: "Purge des services désactivée : un service hors ligne conserve " +
				"son identité indéfiniment.",
			Donnees: DelaiDePurge{Desactivee: true},
		}, nil
	}
	return Resultat{
		Message: fmt.Sprintf(
			"Délai avant suppression d'un service parti : %s. Passé ce délai sans "+
				"battement de cœur, son client est supprimé et il devra se réenrôler.", d),
		Donnees: DelaiDePurge{Delai: d},
	}, nil
}

func reglerDelaiDePurge(a Appelant, p Params) (Resultat, error) {
	brut := strings.TrimSpace(p.Get("hours"))
	if brut == "" {
		return Resultat{}, fmt.Errorf("nombre d'heures requis")
	}
	heures, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("« %s » n'est pas un nombre d'heures", brut)
	}
	// Une durée négative n'a aucun sens et serait enregistrée sans broncher :
	// PurgeDelay traiterait ensuite « <= 0 » comme une désactivation, donc un
	// « -5 » tapé par erreur désactiverait la purge en annonçant l'avoir réglée.
	if heures < 0 {
		return Resultat{}, fmt.Errorf(
			"délai négatif refusé : pour désactiver la purge, réglez explicitement 0")
	}

	if err := hosthandler.SetPurgeDelay(database.GetDatabase(), heures, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("enregistrement du délai : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé le délai de purge des services à %d heure(s)", a.Username, heures))

	if heures == 0 {
		return Resultat{Message: "Purge des services désactivée. Aucun client de " +
			"service ne sera plus supprimé automatiquement."}, nil
	}
	return Resultat{Message: fmt.Sprintf("Délai porté à %d heure(s).", heures)}, nil
}

// RetentionMetriques porte la valeur courante.
//
// Comme DelaiDePurge : zéro signifie « conservation illimitée » et non « purge
// immédiate », et le type dédié force l'appelant à lire lequel des deux.
type RetentionMetriques struct {
	Duree time.Duration

	// Desactivee distingue les deux sens de zéro.
	Desactivee bool
}

func lireRetentionMetriques() (Resultat, error) {
	d := hosthandler.MetricsRetention(database.GetDatabase())
	if d <= 0 {
		return Resultat{
			Message: "Purge des métriques désactivée : la table proxy_metrics grossit " +
				"sans limite. À n'utiliser que si les métriques sont exportées ailleurs.",
			Donnees: RetentionMetriques{Desactivee: true},
		}, nil
	}
	return Resultat{
		Message: fmt.Sprintf(
			"Les métriques de nœuds sont conservées %d jour(s). Au-delà, elles sont "+
				"supprimées — elles ne sont pas résumées, cette table n'agrège pas.",
			int(d.Hours()/24)),
		Donnees: RetentionMetriques{Duree: d},
	}, nil
}

func reglerRetentionMetriques(a Appelant, p Params) (Resultat, error) {
	brut := strings.TrimSpace(p.Get("days"))
	if brut == "" {
		return Resultat{}, fmt.Errorf("nombre de jours requis")
	}
	jours, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("« %s » n'est pas un nombre de jours", brut)
	}
	// Même garde que pour le délai de purge : « -5 » serait enregistré sans
	// broncher, puis lu comme « <= 0 », c'est-à-dire une désactivation annoncée
	// comme un réglage.
	if jours < 0 {
		return Resultat{}, fmt.Errorf(
			"durée négative refusée : pour conserver sans limite, réglez explicitement 0")
	}

	if err := hosthandler.SetMetricsRetention(database.GetDatabase(), jours, a.Username); err != nil {
		return Resultat{}, fmt.Errorf("enregistrement de la rétention : %w", err)
	}

	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a réglé la rétention des métriques à %d jour(s)", a.Username, jours))

	if jours == 0 {
		return Resultat{Message: "Purge des métriques désactivée. La table " +
			"proxy_metrics grossira sans limite."}, nil
	}
	// Le raccourcissement est DIT, parce qu'il détruit au prochain passage.
	return Resultat{Message: fmt.Sprintf(
		"Rétention portée à %d jour(s). Les métriques plus anciennes seront "+
			"supprimées au prochain balayage.", jours)}, nil
}

// --- certificats -------------------------------------------------------------

func listerCertificats(_ Appelant, _ Params) (Resultat, error) {
	certs, err := dbcertificates.GetAllCertificates()
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des certificats : %w", err)
	}
	return Resultat{
		Message: fmt.Sprintf("%d certificat(s).", len(certs)),
		Donnees: certs,
	}, nil
}

// ficheCertificatParNom sert « certificate.get ».
//
// Le nom compte : lireCertificat existe déjà dans actions_certificats.go, où
// c'est une VARIABLE portant l'accès en base par identifiant, remplacée par les
// tests. Les deux ont coexisté sans être vues — le paquet ne compilait pas, et
// rien ne le disait tant que ce paquet-ci n'était pas rebâti.
func ficheCertificatParNom(_ Appelant, p Params) (Resultat, error) {
	nom := p.Get("certificate_name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom de certificat requis")
	}
	certs, err := dbcertificates.GetAllCertificates()
	if err != nil {
		return Resultat{}, fmt.Errorf("lecture des certificats : %w", err)
	}
	for _, c := range certs {
		if c.Name != nom {
			continue
		}
		// La clé PRIVÉE est écartée avant de rendre la fiche.
		//
		// Elle n'a aucune raison de traverser une session d'administration, et
		// la retirer ICI plutôt que dans chaque façade garantit qu'aucune ne
		// puisse l'oublier. L'interface web le faisait déjà ; la ligne de
		// commande ne l'affichait pas, mais rien ne l'en empêchait.
		c.PrivateKeyData = nil
		return Resultat{Message: "Certificat " + nom + ".", Donnees: &c}, nil
	}
	return Resultat{}, fmt.Errorf("certificat %q introuvable", nom)
}
