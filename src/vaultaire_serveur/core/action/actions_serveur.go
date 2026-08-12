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
		UnDomaineSuffit: true,
		FiltreInutile: "un nœud de cluster n'appartient à aucun domaine ; il n'y a " +
			"pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les nœuds du cluster",
		Executer: listerNoeuds,
	})

	r.MustEnregistrer(Definition{
		Nom:             "cluster.get_purge_delay",
		CleRBAC:         permission.ActionReadCluster,
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
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

	// --- certificats ---

	r.MustEnregistrer(Definition{
		Nom:             "certificate.list",
		CleRBAC:         permission.ActionReadCertificate,
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
		FiltreInutile: "un certificat TLS n'appartient à aucun domaine ; il n'y a " +
			"pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les certificats du serveur",
		Executer: listerCertificats,
	})

	r.MustEnregistrer(Definition{
		Nom:             "certificate.get",
		CleRBAC:         permission.ActionReadCertificate,
		Portee:          PorteeGlobale,
		UnDomaineSuffit: true,
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

	message := fmt.Sprintf("%d nœud(s).", len(noeuds))
	if role != "" {
		message = fmt.Sprintf("%d nœud(s) actif(s) pour le rôle %s.", len(noeuds), role)
	}
	return Resultat{Message: message, Donnees: NoeudsCluster{Role: role, Noeuds: noeuds}}, nil
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
