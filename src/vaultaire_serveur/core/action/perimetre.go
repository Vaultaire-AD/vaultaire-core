package action

import (
	"fmt"

	"vaultaire/core/logs"
	"vaultaire/core/permission"
)

// Filtrage des listes par domaine.
//
// # Pourquoi ce fichier a quitté le serveur web
//
// Il y vivait seul. Les pages d'administration filtraient leurs listes — un
// délégué de compta.example.fr ne voyait que compta — tandis que la ligne de
// commande ne filtrait rien : `get -u` rendait l'annuaire entier dès qu'on
// avait `read:get:user` quelque part.
//
// Le contrôle des ÉCRITURES était pourtant identique des deux côtés. Seule la
// visibilité divergeait, et dans le sens le plus gênant : la divulgation que
// le modèle de délégation existe précisément pour empêcher restait ouverte par
// la porte de derrière.
//
// # Ce que le filtrage n'est pas
//
// Ce n'est pas un second contrôle d'accès. Le contrôle décide si l'action a
// lieu ; le filtrage décide ce que la réponse contient. Une action de lecture
// autorisée peut légitimement ne rien rendre — parce que rien, dans la liste,
// n'appartient au périmètre de l'appelant.
//
// # Coût assumé
//
// Résoudre le domaine d'une entité demande une requête, donc une liste de N
// entités en demande N. Le cache ci-dessous les dédoublonne à l'échelle d'un
// appel. Si un jour cela pèse, la réponse est de filtrer en SQL — pas de
// retirer le filtre.

// Perimetre décide de la VISIBILITÉ d'une entité, domaine par domaine.
//
// Une interface plutôt qu'une structure concrète : les tests posent un
// périmètre fictif — « cet appelant voit paris, pas lyon » — et observent ce
// que les actions rendent, sans annuaire.
type Perimetre interface {
	// Global dit que le périmètre couvre tout : le filtrage est alors inutile,
	// et surtout on évite N résolutions de domaines pour rien.
	Global() bool

	// AutoriseUnDes rend vrai si AU MOINS UN des domaines est dans le
	// périmètre.
	//
	// « au moins un » et non « tous » : il s'agit de décider si l'entité est
	// visible, pas si elle est modifiable. Un compte présent dans un domaine
	// que j'administre m'est légitimement visible même s'il appartient aussi à
	// un domaine qui m'échappe — et c'est justement ce qui doit m'empêcher
	// d'agir dessus, ce que la voie stricte vérifie de son côté.
	AutoriseUnDes(domaines []string) bool

	// DomainesDe résout les domaines d'une entité, avec cache.
	//
	// # Pourquoi une méthode paramétrée plutôt qu'une par genre
	//
	// La première version portait DomainesUtilisateur, DomainesClient et
	// DomainesPermission. Chaque nouveau genre d'entité — permission client,
	// GPO — ajoutait une méthode, donc cassait toutes les implémentations, y
	// compris les doublures de test. La rupture était utile la première fois
	// (elle force à répondre) et purement mécanique les suivantes.
	//
	// Le genre est un type nommé et non une chaîne libre : une faute de frappe
	// ne compile pas, là où « utilisateurr » aurait rendu une liste vide, donc
	// masqué l'entité sans le dire.
	//
	// Le cache est porté par le périmètre et non par des fonctions libres : il
	// doit vivre le temps d'un appel et pas au-delà, sans quoi une liste
	// refléterait des rattachements périmés.
	DomainesDe(genre GenreEntite, identifiant string) []string
}

// GenreEntite désigne ce qu'on cherche à situer dans les domaines.
type GenreEntite string

const (
	EntiteUtilisateur      GenreEntite = "utilisateur"
	EntiteClient           GenreEntite = "client"
	EntitePermission       GenreEntite = "permission"
	EntitePermissionClient GenreEntite = "permission_client"
	EntiteGPO              GenreEntite = "gpo"
	EntiteGroupe           GenreEntite = "groupe"
)

// ResolveurPerimetre construit le périmètre d'un appelant pour une clé RBAC.
type ResolveurPerimetre interface {
	Perimetre(groupIDs []int, cle string) Perimetre
}

// --- implémentation réelle ---------------------------------------------------

// PerimetreVaultaire branche le filtrage sur core/permission.
type PerimetreVaultaire struct{}

func (PerimetreVaultaire) Perimetre(groupIDs []int, cle string) Perimetre {
	return &perimetreReel{
		autorises: permission.DomainsWhereAllowed(groupIDs, cle),
		cache:     make(map[string][]string),
	}
}

type perimetreReel struct {
	autorises permission.AllowedDomains
	cache     map[string][]string
}

func (p *perimetreReel) Global() bool { return p.autorises.Global }

func (p *perimetreReel) AutoriseUnDes(domaines []string) bool {
	if p.autorises.Global {
		return true
	}
	for _, d := range domaines {
		if p.autorises.Allows(d) {
			return true
		}
	}
	return false
}

func (p *perimetreReel) DomainesDe(genre GenreEntite, id string) []string {
	cle := string(genre) + ":" + id
	if connu, ok := p.cache[cle]; ok {
		return connu
	}

	var domaines []string
	var err error
	switch genre {
	case EntiteUtilisateur:
		domaines, err = permission.GetDomainListFromUsername(id)
	case EntiteClient:
		domaines, err = permission.GetDomainsFromClientByComputerID(id)
	case EntitePermission:
		domaines, err = permission.GetDomainslistFromUserpermission(id)
	case EntitePermissionClient:
		domaines, err = permission.GetDomainslistFromClientpermission(id)
	case EntiteGPO:
		domaines, err = permission.GetDomainslistFromGPO(id)
	case EntiteGroupe:
		domaines, err = permission.GetDomainsFromGroupName(id)
	default:
		// Genre inconnu : l'entité est masquée, et le dire fort.
		//
		// Fail-closed sur une valeur que le compilateur ne peut pas garantir
		// exhaustive. Rendre « tous les domaines » ici ferait passer l'entité
		// dans toutes les listes, sur la foi d'un genre que personne n'a
		// implémenté.
		logs.Write_Log("WARNING", fmt.Sprintf(
			"action: genre d'entité inconnu %q pour %q — entrée masquée", genre, id))
		p.cache[cle] = nil
		return nil
	}

	if err != nil {
		// Domaines illisibles : l'entité est MASQUÉE.
		//
		// Une liste filtrée ne doit pas laisser passer ce qu'elle n'a pas su
		// classer. Le choix inverse — montrer dans le doute — ferait de la
		// moindre panne de lecture une divulgation.
		logs.Write_Log("DEBUG", "action: domaines de "+cle+" illisibles, entrée masquée")
		domaines = nil
	}
	p.cache[cle] = domaines
	return domaines
}

// --- application du filtre ---------------------------------------------------

// perimetreDe construit le périmètre d'un appel, ou rend nil.
//
// Nil quand aucun résolveur n'est câblé : le filtre déclaré par l'action n'est
// alors PAS appliqué. C'est le seul endroit du registre où l'absence d'un
// composant ne provoque pas de refus, et c'est délibéré — un filtre absent ne
// donne aucun droit supplémentaire, il élargit seulement l'affichage. Le
// refuser rendrait toute lecture impossible sur un exécuteur incomplet, ce qui
// serait pire.
func (e *Executeur) perimetreDe(d Definition, a Appelant) Perimetre {
	if e.Perimetres == nil || d.Filtre == nil || d.CleRBAC == "" {
		return nil
	}
	return e.Perimetres.Perimetre(a.GroupIDs, d.CleRBAC)
}

// appliquerFiltre réduit les données au périmètre de l'appelant.
func appliquerFiltre(d Definition, res Resultat, perim Perimetre, username string) Resultat {
	if d.Filtre == nil || perim == nil {
		return res
	}
	if perim.Global() {
		// Rien à masquer, et surtout aucune résolution de domaine à faire.
		return res
	}

	donnees, masques := d.Filtre(res.Donnees, perim)
	res.Donnees = donnees

	if masques > 0 {
		// Journalisé pour que la différence entre « il n'y a rien » et « vous
		// n'avez pas le droit de voir » reste explicable sans lire le code :
		// un délégué qui trouve sa liste vide doit pouvoir obtenir une réponse.
		logs.Write_Log("DEBUG", fmt.Sprintf(
			"action %s : %d entrée(s) masquée(s) hors du périmètre de %s",
			d.Nom, masques, username))

		// Le message dit ce qui a été retiré.
		//
		// Sans cela, une liste tronquée se lit comme une liste complète — et
		// c'est ainsi qu'on croit un annuaire vide alors qu'on n'en voit
		// qu'une part.
		res.Message = fmt.Sprintf("%s (%d entrée(s) hors de votre périmètre non affichée(s))",
			res.Message, masques)
	}
	return res
}
