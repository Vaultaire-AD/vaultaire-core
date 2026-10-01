package action

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	newclient "vaultaire/ducky-network/new_client"
)

// Actions sur les machines du parc.
//
// # Une asymétrie à connaître
//
// Créer une machine ne crée pas un enregistrement au sens ordinaire : cela
// GÉNÈRE UNE IDENTITÉ — un identifiant et une paire de clés — que l'on
// installera ensuite sur un poste. Supprimer une machine, à l'inverse, ne
// désinstalle rien : l'agent continue de tourner là-bas, il ne sera simplement
// plus reconnu.
//
// Cette asymétrie explique pourquoi la suppression rend un message qui le dit.
// Un administrateur qui lit « Machine supprimée » sans autre précision peut
// croire le poste nettoyé, alors que l'agent y reste installé et qu'un compte
// local peut y subsister.

// EnregistrerActionsClient ajoute les actions machine au registre.
func EnregistrerActionsClient(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "client.create",
		CleRBAC: "write:create:client",
		// La machine n'existe pas encore : aucun domaine dont déduire la portée.
		Portee:   PorteeGlobale,
		Resume:   "génère l'identité d'une nouvelle machine",
		Executer: creerClient,
	})

	r.MustEnregistrer(Definition{
		Nom: "client.export",
		// Même clé que la création, parce que la décision du 82 le demande — et
		// ce n'est PAS parce que les deux gestes se valent.
		//
		// La création produit une identité NEUVE : aucun groupe, aucune GPO,
		// aucun tunnel. L'export produit l'identité d'une machine EXISTANTE et
		// provisionnée — rattachée à des groupes, destinataire de politiques, et
		// porteuse d'un tunnel machine si elle est serveur. Se faire passer pour
		// un serveur du parc n'est pas « ce que la création produit ».
		//
		// Conséquence à connaître : on ne peut pas accorder « créer une machine »
		// sans accorder « exporter l'identité de n'importe laquelle ». Ce qui
		// borne le risque aujourd'hui, c'est la PORTÉE GLOBALE ci-dessous — la
		// clé est exigée sur « * », donc un délégué de domaine ne peut pas
		// exporter. Une clé propre (write:export:client) est la bonne suite si
		// ce couplage devient gênant.
		CleRBAC: "write:create:client",
		// Globale, comme la création : l'archive ne dépend d'aucun domaine, et
		// une machine fraîchement créée n'en a encore aucun.
		Portee:   PorteeGlobale,
		Resume:   "compose l'archive d'installation d'une machine",
		Executer: exporterClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client.update",
		CleRBAC:  "write:update:client",
		Portee:   PorteeClient,
		Resume:   "met à jour l'inventaire d'une machine",
		Executer: modifierClient,
	})

	r.MustEnregistrer(Definition{
		Nom:      "client.delete",
		CleRBAC:  "write:delete:client",
		Portee:   PorteeClient,
		Resume:   "retire une machine de l'annuaire",
		Executer: supprimerClient,
	})
}

// creerClient génère l'identité d'une machine.
//
// Le TYPE n'est pas demandé : ce chemin ne peut créer qu'un client basic. Un
// client service s'enrôle lui-même avec sa propre paire de clés — il ne se crée
// pas depuis l'administration, puisque sa clé privée ne doit jamais quitter
// l'hôte qui l'utilisera.
func creerClient(_ Appelant, p Params) (Resultat, error) {
	// Le web lisait `is_serveur == "1"`, une convention de formulaire. On
	// accepte aussi les formes qu'écrirait une ligne de commande, sans quoi
	// l'action ne serait utilisable que depuis le navigateur.
	estServeur, err := booleenPermissif(p.Get("is_serveur"))
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur is_serveur invalide : %w", err)
	}

	computeurID, err := newclient.GenerateClientSoftware(estServeur)
	if err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la création de la machine : %w", err)
	}

	return Resultat{
		Message: fmt.Sprintf("Machine créée, identifiant %s.", computeurID),
		Donnees: map[string]string{"computeur_id": computeurID},
	}, nil
}

// ArchiveClient porte l'archive composée, hors du message.
//
// Hors du message PARCE QUE le message d'exécution est recopié dans les
// journaux : une archive — donc une clé privée — n'a rien à y faire. Même
// règle que le secret d'enrôlement, pour la même raison.
type ArchiveClient struct {
	ComputeurID string
	Systeme     string
	NomFichier  string
	Contenu     []byte
}

// exporterClient compose l'archive d'installation d'une machine existante.
//
// Ne crée rien : la machine doit exister. Ce qui est produit à chaque appel, ce
// sont les fichiers COMPAGNONS — empreinte du core, liste des cores, clé de
// signature —, parce qu'ils suivent l'état du cluster et qu'une copie figée
// vieillirait mal.
func exporterClient(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("computeur_id")
	if cible == "" {
		return Resultat{}, fmt.Errorf("computeur_id est requis")
	}

	contenu, nomFichier, err := newclient.ConstruireArchive(
		database.GetDatabase(), cible, p.Get("systeme"))
	if err != nil {
		return Resultat{}, err
	}

	systeme, _ := newclient.SystemeValide(p.Get("systeme"))
	return Resultat{
		// Le message dit la taille et le système, jamais le contenu. Ce n'est
		// pas lui qui part aux journaux — le registre y écrit sa propre ligne,
		// « <qui> a fait client.export sur <cible> » — mais il s'affiche, et une
		// archive n'a pas plus à s'afficher qu'à se journaliser.
		Message: fmt.Sprintf("Archive composée pour %s (%s, %d octets).", cible, systeme, len(contenu)),
		Donnees: ArchiveClient{
			// Normalisé, comme ce qu'a reçu ConstruireArchive : sinon le jeton,
			// le nom de fichier et la ligne SECURITY divergent d'un espace.
			ComputeurID: strings.TrimSpace(cible),
			Systeme:     systeme,
			NomFichier:  nomFichier,
			Contenu:     contenu,
		},
	}, nil
}

// booleenPermissif accepte « 1 » en plus des formes de booleen().
//
// Le formulaire des machines emploie la valeur « 1 » là où celui des groupes
// emploie « on ». Les deux conventions coexistent dans les gabarits ; les
// unifier demanderait de les modifier tous, ce qui n'est pas le sujet de ce
// portage — et une valeur mal interprétée créerait ici une machine du mauvais
// type, ce qui ne se verrait qu'à l'usage.
func booleenPermissif(v string) (bool, error) {
	return booleen(v)
}

// modifierClient met à jour l'inventaire matériel.
//
// Les champs absents ne sont pas touchés. L'ancienne version web passait
// systématiquement les quatre valeurs du formulaire : un formulaire partiel
// effaçait donc les champs qu'il ne portait pas — un inventaire réduit à des
// chaînes vides après une simple correction de nom d'hôte.
func modifierClient(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("computeur_id")
	if cible == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	db := database.GetDatabase()
	courant, err := dbclients.Command_GET_ClientByComputeurID(db, cible)
	if err != nil || courant == nil {
		return Resultat{}, fmt.Errorf("machine %q introuvable", cible)
	}

	hostname := valeurOuCourante(p, "hostname", courant.Hostname)
	systeme := valeurOuCourante(p, "os", courant.OS)
	ram := valeurOuCourante(p, "ram", courant.RAM)
	// Processeur est un entier en base mais une chaîne dans UpdateHostname.
	// La conversion est faite ici, une fois, plutôt que laissée à chaque
	// appelant — c'est le genre d'écart qui produit un « 0 » là où il y avait
	// un nombre de cœurs.
	proc := valeurOuCourante(p, "proc", strconv.Itoa(courant.Processeur))

	// Les VERSIONS sont repassées telles quelles, jamais éditables.
	//
	// Elles décrivent ce qui TOURNE sur la machine — c'est elle qui les déclare
	// dans son inventaire. Laisser un administrateur les corriger produirait une
	// vue qui dit ce qu'on aimerait plutôt que ce qui est, et c'est justement
	// dans cette vue qu'on ira chercher qui n'est pas à jour.
	//
	// Les repasser est indispensable : UpdateHostname écrit systématiquement
	// toutes les colonnes, donc les omettre les effacerait à chaque correction
	// de nom d'hôte. C'est le défaut que `valeurOuCourante` corrige déjà pour
	// les champs matériels.
	if err := dbclients.UpdateHostname(db, cible, hostname, systeme, ram, proc,
		courant.AgentVersion, courant.SDKVersion); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la mise à jour de la machine %q : %w", cible, err)
	}

	res := Resultat{Message: fmt.Sprintf("Machine %s mise à jour.", cible)}
	if maj, err := dbclients.Command_GET_ClientByComputeurID(db, cible); err == nil {
		res.Donnees = maj
	}
	return res, nil
}

// valeurOuCourante rend la valeur fournie, ou celle déjà en base si le champ
// n'a pas été transmis.
//
// Presente et non Get : un champ transmis vide veut dire « effacer », un champ
// absent veut dire « ne pas toucher ». Les confondre est précisément ce qui
// effaçait l'inventaire.
func valeurOuCourante(p Params, nom, courante string) string {
	if p.Presente(nom) {
		return p.Get(nom)
	}
	return courante
}

// supprimerEnBaseClient : l'accès à la base, isolé derrière une variable.
//
// Même raison que pour les certificats (actions_certificats.go) : le test qui
// vérifie le MESSAGE de suppression ne mesure qu'une chaîne, et n'a aucune
// raison d'exiger une base vivante. Sans elle, database.GetDatabase() rend nil
// et l'appel panique — ce qui emporte le binaire de test du paquet entier, pas
// seulement ce contrôle.
var supprimerEnBaseClient = dbclients.Command_DELETE_ClientWithComputeurID

// supprimerClient retire la machine de l'annuaire.
func supprimerClient(_ Appelant, p Params) (Resultat, error) {
	cible := p.Get("computeur_id")
	if cible == "" {
		return Resultat{}, fmt.Errorf("identifiant de machine requis")
	}

	if err := supprimerEnBaseClient(database.GetDatabase(), cible); err != nil {
		return Resultat{}, fmt.Errorf("erreur lors de la suppression de la machine %q : %w", cible, err)
	}

	// Le message dit ce que la suppression NE fait PAS.
	//
	// L'ancienne version rendait « Client supprimé. », ce qui laisse croire au
	// nettoyage du poste. Or l'agent y tourne toujours, avec sa clé privée et
	// les comptes locaux qu'il a créés — il ne sera simplement plus reconnu par
	// le core. Un administrateur qui compte sur cette action pour retirer un
	// poste compromis se tromperait.
	return Resultat{
		Message: fmt.Sprintf(
			"Machine %s retirée de l'annuaire. L'agent reste installé sur le poste et "+
				"n'est pas désinstallé ; les comptes locaux qu'il a créés y subsistent.",
			cible),
	}, nil
}
