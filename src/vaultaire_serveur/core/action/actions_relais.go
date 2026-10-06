package action

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	clusterdatabase "vaultaire/cluster/cluster_database"
	clusterstorage "vaultaire/cluster/cluster_storage"
	"vaultaire/core/database"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	hosthandler "vaultaire/ducky-network/host_handler"
)

// Les relais d'un proxy, pilotés depuis le core — TO-DO 141.
//
// # Ce que ces actions remplacent
//
// Un fichier YAML sur la machine du proxy, et un redémarrage. « Qui expose
// quoi » — Ducky, HTTPS, LDAPS, sur quel port, vers quelles cibles — ne se
// lisait et ne se changeait que là. Le core n'en affichait que des compteurs.
//
// # Où vit la vérité
//
// Dans le fichier TANT QUE le core n'a rien décidé pour ce proxy : il applique
// son fichier, le dit, et c'est ce que `cluster.relay_list` rend. À la
// première écriture, le core PREND LA MAIN : il repart de ce que le proxy
// faisait tourner — pour qu'ajouter un relais ne retire pas ceux du fichier —
// et sa liste fait foi. `cluster.relay_release` la rend.
//
// # Ce que le core ne décide pas
//
// S'il a obtenu un port. Chaque relais demandé a un état — demandé, appliqué,
// refusé — et seul le proxy fait passer du premier aux deux autres.
//
// # Les droits
//
// Lire : `read:cluster`, comme le reste de l'état du cluster. Écrire :
// `write:relay`, une clé à part — voir permission.ActionWriteRelay.

// EnregistrerActionsRelais ajoute les actions de pilotage des relais.
func EnregistrerActionsRelais(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "cluster.relay_list",
		CleRBAC: permission.ActionReadCluster,
		Portee:  PorteeGlobale,
		// Inerte sous PorteeGlobale, déclaré pour l'invariant — voir
		// cluster.get_purge_delay.
		UnDomaineSuffit: true,
		Resume:          "affiche les relais d'un proxy : configuration, cibles, état et compteurs",
		Executer:        listerRelais,
	})

	r.MustEnregistrer(Definition{
		Nom:      "cluster.relay_set",
		CleRBAC:  permission.ActionWriteRelay,
		Portee:   PorteeGlobale,
		Resume:   "ajoute ou modifie un relais d'un proxy",
		Executer: poserRelais,
	})

	r.MustEnregistrer(Definition{
		Nom:      "cluster.relay_remove",
		CleRBAC:  permission.ActionWriteRelay,
		Portee:   PorteeGlobale,
		Resume:   "retire un relais d'un proxy",
		Executer: retirerRelais,
	})

	r.MustEnregistrer(Definition{
		Nom: "cluster.relay_release",
		// La même clé que poser un relais : rendre la main fait rouvrir au
		// proxy ce que dit son fichier, et fermer ce que le core avait posé.
		CleRBAC:  permission.ActionWriteRelay,
		Portee:   PorteeGlobale,
		Resume:   "rend au proxy la main sur ses relais : il réapplique son fichier",
		Executer: rendreLaMainSurLesRelais,
	})
}

// RelaisDuNoeud porte la réponse de cluster.relay_list.
type RelaisDuNoeud struct {
	Noeud   string
	Role    string
	EnLigne bool
	Vue     clusterstorage.VueRelais
}

// noeudProxy relit un nœud et refuse ce qui n'est pas un proxy.
//
// Un core ne relaie rien, et un service — le Nexus, l'interface web — a ses
// propres écoutes : poser une liste de relais sur l'un d'eux écrirait en base
// une demande que personne ne lira jamais.
func noeudProxy(p Params) (clusterstorage.Node, string, error) {
	hostname := p.Get("node")
	if hostname == "" {
		hostname = p.Get("hostname")
	}
	if hostname == "" {
		return clusterstorage.Node{}, "", fmt.Errorf("nom du proxy requis")
	}
	db := database.GetDatabase()
	n, err := clusterdatabase.NoeudParHostname(db, hostname)
	if err != nil {
		return n, "", err
	}
	if n.Role != "proxy" {
		return n, "", fmt.Errorf("%s est un nœud de rôle « %s » : seuls les proxies portent des relais", n.Hostname, n.Role)
	}
	proprietaire, err := clusterdatabase.ProprietaireDuNoeud(db, n.Hostname)
	if err != nil {
		return n, "", err
	}
	if strings.TrimSpace(proprietaire) == "" {
		return n, "", fmt.Errorf("le proxy %s n'a pas de propriétaire connu : il doit se réenregistrer avant d'être piloté", n.Hostname)
	}
	return n, proprietaire, nil
}

func listerRelais(_ Appelant, p Params) (Resultat, error) {
	n, proprietaire, err := noeudProxy(p)
	if err != nil {
		return Resultat{}, err
	}
	db := database.GetDatabase()

	demande, etat, err := clusterdatabase.RelaisDemandes(db, proprietaire)
	if err != nil {
		return Resultat{}, err
	}
	rapport, err := clusterdatabase.DernierCompteRendu(db, proprietaire)
	if err != nil {
		return Resultat{}, err
	}

	var mesures []clusterstorage.RelaisMesure
	noeuds := []clusterstorage.Node{n}
	clusterdatabase.GarnirMetriquesRelais(db, noeuds)
	if noeuds[0].Relais != nil {
		mesures = noeuds[0].Relais.Relais
	}

	vue := clusterstorage.ComposerVueRelais(demande, etat.RevisionDemandee(), rapport, mesures, time.Now())
	vue.ModifiePar, vue.ModifieLe = etat.ModifiePar, etat.ModifieLe

	return Resultat{
		Message: n.Hostname + " : " + vue.Resume(),
		Donnees: RelaisDuNoeud{Noeud: n.Hostname, Role: n.Role, EnLigne: n.Status == "online", Vue: vue},
	}, nil
}

// baseDeLaDemande rend la liste sur laquelle une écriture s'applique, et le
// port Ducky annoncé par le proxy.
//
// # La première écriture PREND LA MAIN
//
// Si le core ne pilote pas encore ce proxy, la base n'est pas une liste vide :
// c'est ce que le proxy fait tourner d'après son fichier. Partir de rien
// ferait d'« ajouter un relais HTTPS » le retrait de tous les autres, relais
// Ducky compris — donc une liste que le proxy refuserait en entier, au mieux.
//
// Cela exige un compte rendu : un proxy antérieur à la 2.2 n'en envoie pas, et
// le core ne peut pas prendre la main sur une configuration qu'il n'a pas vue.
func baseDeLaDemande(proprietaire, hostname string, portDuNoeud int) ([]clusterstorage.RelaisConfig, int, error) {
	db := database.GetDatabase()
	demande, etat, err := clusterdatabase.RelaisDemandes(db, proprietaire)
	if err != nil {
		return nil, 0, err
	}
	rapport, err := clusterdatabase.DernierCompteRendu(db, proprietaire)
	if err != nil {
		return nil, 0, err
	}
	if rapport == nil {
		return nil, 0, fmt.Errorf(
			"le proxy %s n'a jamais rendu compte de ses relais : il est d'une version antérieure à la 2.2, "+
				"ou ne s'est pas connecté depuis la mise à jour du core. Le core ne peut pas piloter une configuration qu'il n'a pas vue",
			hostname)
	}
	if !rapport.Pilotage {
		return nil, 0, fmt.Errorf(
			"le proxy %s garde la main sur ses relais : son fichier de configuration porte « pilotage_par_le_core: false ». "+
				"Retirez cette ligne et redémarrez-le, ou modifiez son fichier", hostname)
	}
	port := rapport.PortAnnonce
	if port == 0 {
		port = portDuNoeud
	}
	if !etat.Pilote {
		demande = clusterstorage.DepuisLeCompteRendu(*rapport)
	}
	return demande, port, nil
}

// enregistrerEtPousser contrôle la liste, l'écrit, la trace et l'envoie.
func enregistrerEtPousser(a Appelant, n clusterstorage.Node, proprietaire string,
	avant, apres []clusterstorage.RelaisConfig, portAnnonce int, geste string) (Resultat, error) {

	if err := clusterstorage.ValiderListeDeRelais(apres, portAnnonce); err != nil {
		return Resultat{}, err
	}
	db := database.GetDatabase()
	revision, err := clusterdatabase.EcrireRelaisDemandes(db, proprietaire, apres, a.Username)
	if err != nil {
		return Resultat{}, err
	}

	// Trace SECURITY, avec l'état AVANT. Ce qu'un proxy expose est un point
	// d'entrée du réseau : six mois plus tard, c'est « qui a ouvert ce port,
	// et vers quoi » qu'on cherchera, et « le relais vaut X » ne le dit pas.
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a %s sur le proxy %s (révision %d) — avant : %s ; après : %s",
		a.Username, geste, n.Hostname, revision, resumeDesRelais(avant), resumeDesRelais(apres)))

	return Resultat{
		Message: fmt.Sprintf("%s : %s (révision %d). %s", n.Hostname, geste, revision, suiteDeLaPoussee(proprietaire, n.Hostname)),
	}, nil
}

// suiteDeLaPoussee envoie la liste au proxy et dit ce qu'il va se passer.
func suiteDeLaPoussee(proprietaire, hostname string) string {
	envoye, err := hosthandler.PousserRelais(database.GetDatabase(), proprietaire)
	switch {
	case err != nil:
		return "L'envoi immédiat a échoué (" + err.Error() + ") : le proxy la recevra à son prochain compte rendu, " +
			"dans la minute. État : « cluster relais " + hostname + " »."
	case envoye:
		return "Envoyée au proxy, qui l'applique sans redémarrer et rend compte de ce qu'il a obtenu. " +
			"État : « cluster relais " + hostname + " »."
	default:
		return "Le proxy n'est pas raccordé à ce core en ce moment : il la recevra à son prochain compte rendu — " +
			"dans la minute s'il est en ligne, à son retour sinon. État : « cluster relais " + hostname + " »."
	}
}

// resumeDesRelais rend une liste en une ligne, pour le journal.
func resumeDesRelais(liste []clusterstorage.RelaisConfig) string {
	if len(liste) == 0 {
		return "aucun relais"
	}
	parts := make([]string, 0, len(liste))
	for _, r := range liste {
		detail := fmt.Sprintf("%s (%s %s → %s", r.Nom, r.Type, r.Ecoute, r.SourceLisible())
		// Les réglages ne figurent que s'ils sont posés : c'est ce qui fait
		// qu'une modification d'un seul plafond se lit dans la ligne, et que
		// les relais laissés à leurs défauts ne l'allongent pas.
		for _, reglage := range []struct {
			libelle string
			valeur  int
		}{
			{"délai", r.DelaiConnexionSecondes}, {"inactivité", r.InactiviteSecondes},
			{"max", r.MaxConnexions}, {"max par source", r.MaxParSource},
		} {
			if reglage.valeur != 0 {
				detail += fmt.Sprintf(" ; %s %d", reglage.libelle, reglage.valeur)
			}
		}
		parts = append(parts, detail+")")
	}
	return strings.Join(parts, ", ")
}

// entier lit un paramètre numérique facultatif.
func entier(p Params, nom, libelle string) (int, error) {
	brut := p.Get(nom)
	if brut == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(brut)
	if err != nil {
		return 0, fmt.Errorf("%s invalide : %q n'est pas un nombre", libelle, brut)
	}
	return n, nil
}

// decouperLesAdresses accepte virgules, espaces et retours à la ligne : la
// commande les sépare par des virgules, le formulaire par des lignes.
func decouperLesAdresses(brut string) []string {
	var out []string
	for _, a := range strings.FieldsFunc(brut, func(r rune) bool {
		return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t'
	}) {
		if a = strings.TrimSpace(a); a != "" {
			out = append(out, a)
		}
	}
	return out
}

// poserRelais ajoute un relais, ou modifie celui qui porte ce nom.
//
// # Seuls les champs TRANSMIS changent
//
// Sur un relais qui existe, un paramètre absent veut dire « n'y touche pas ».
// C'est ce qui permet à « cluster relais proxy1 set nexus --max 200 » de
// changer un plafond sans avoir à redire le port et la source — et sans les
// remettre à leur défaut, ce qui déplacerait un relais qu'on voulait
// seulement borner.
func poserRelais(a Appelant, p Params) (Resultat, error) {
	n, proprietaire, err := noeudProxy(p)
	if err != nil {
		return Resultat{}, err
	}
	nom := p.Get("name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom du relais requis")
	}
	avant, port, err := baseDeLaDemande(proprietaire, n.Hostname, n.Port)
	if err != nil {
		return Resultat{}, err
	}

	apres := append([]clusterstorage.RelaisConfig(nil), avant...)
	rang := -1
	for i := range apres {
		if strings.EqualFold(apres[i].Nom, nom) {
			rang = i
			break
		}
	}
	var r clusterstorage.RelaisConfig
	if rang >= 0 {
		r = apres[rang]
	} else {
		r.Nom = nom
	}

	if p.Presente("type") && p.Get("type") != "" {
		r.Type = p.Get("type")
	}
	if p.Presente("listen") {
		r.Ecoute = p.Get("listen")
	}
	if p.Presente("source") && p.Get("source") != "" {
		r.Cibles.Source = p.Get("source")
		// Changer de source vide ce qui ne vaut que pour l'ancienne : une
		// liste d'adresses laissée sous « cores » serait une donnée morte, et
		// un port cible laissé sous « liste » ferait refuser le relais.
		if r.Cibles.Source != clusterstorage.SourceListe {
			r.Cibles.Adresses = nil
		}
		if r.Cibles.Source != clusterstorage.SourceCores {
			r.Cibles.Port = 0
		}
	}
	if p.Presente("addresses") {
		r.Cibles.Adresses = decouperLesAdresses(p.Get("addresses"))
		if len(r.Cibles.Adresses) > 0 && !p.Presente("source") {
			r.Cibles.Source = clusterstorage.SourceListe
			r.Cibles.Port = 0
		}
	}
	for _, champ := range []struct {
		nom, libelle string
		cible        *int
	}{
		{"target_port", "port cible", &r.Cibles.Port},
		{"connect_timeout", "délai de connexion", &r.DelaiConnexionSecondes},
		{"idle", "inactivité", &r.InactiviteSecondes},
		{"max_connections", "plafond de connexions", &r.MaxConnexions},
		{"max_per_source", "plafond par source", &r.MaxParSource},
	} {
		if !p.Presente(champ.nom) {
			continue
		}
		v, err := entier(p, champ.nom, champ.libelle)
		if err != nil {
			return Resultat{}, err
		}
		*champ.cible = v
	}

	geste := "ajouté le relais " + nom
	if rang >= 0 {
		apres[rang] = r
		geste = "modifié le relais " + nom
	} else {
		apres = append(apres, r)
	}
	return enregistrerEtPousser(a, n, proprietaire, avant, apres, port, geste)
}

func retirerRelais(a Appelant, p Params) (Resultat, error) {
	n, proprietaire, err := noeudProxy(p)
	if err != nil {
		return Resultat{}, err
	}
	nom := p.Get("name")
	if nom == "" {
		return Resultat{}, fmt.Errorf("nom du relais requis")
	}
	avant, port, err := baseDeLaDemande(proprietaire, n.Hostname, n.Port)
	if err != nil {
		return Resultat{}, err
	}
	var apres []clusterstorage.RelaisConfig
	trouve := false
	for _, r := range avant {
		if strings.EqualFold(r.Nom, nom) {
			trouve = true
			if r.Type == clusterstorage.RelaisDucky {
				return Resultat{}, fmt.Errorf(
					"le relais Ducky « %s » ne se retire pas : %s est annoncé aux agents comme un nœud Ducky, "+
						"et sans ce relais ils s'y présenteraient pour rien. Pour sortir ce proxy du service, "+
						"retirez-le de la rotation : « cluster rotation %s out »", r.Nom, n.Hostname, n.Hostname)
			}
			continue
		}
		apres = append(apres, r)
	}
	if !trouve {
		return Resultat{}, fmt.Errorf("aucun relais « %s » sur le proxy %s", nom, n.Hostname)
	}
	return enregistrerEtPousser(a, n, proprietaire, avant, apres, port, "retiré le relais "+nom)
}

func rendreLaMainSurLesRelais(a Appelant, p Params) (Resultat, error) {
	n, proprietaire, err := noeudProxy(p)
	if err != nil {
		return Resultat{}, err
	}
	db := database.GetDatabase()
	avant, etat, err := clusterdatabase.RelaisDemandes(db, proprietaire)
	if err != nil {
		return Resultat{}, err
	}
	if !etat.Pilote {
		return Resultat{Message: n.Hostname + " : le core ne pilote pas ces relais, il n'y a rien à rendre."}, nil
	}
	if err := clusterdatabase.RendreLaMainAuFichier(db, proprietaire, a.Username); err != nil {
		return Resultat{}, err
	}
	logs.Write_Log("SECURITY", fmt.Sprintf(
		"%s a rendu au proxy %s la main sur ses relais : il réapplique son fichier de configuration — la liste du core était : %s",
		a.Username, n.Hostname, resumeDesRelais(avant)))

	return Resultat{Message: n.Hostname + " : la main est rendue au fichier de configuration du proxy. " +
		suiteDeLaPoussee(proprietaire, n.Hostname)}, nil
}
