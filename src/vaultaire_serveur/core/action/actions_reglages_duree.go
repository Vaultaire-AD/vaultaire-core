package action

import (
	"fmt"
	"strconv"
	"strings"

	"vaultaire/core/database"
	dbclients "vaultaire/core/database/db_clients"
	"vaultaire/core/logs"
	"vaultaire/core/parcversion"
	"vaultaire/core/permission"
	"vaultaire/core/reglages"
)

// Actions sur les durées d'exploitation.
//
// # La clé retenue
//
// `write:server`, la même que le mode debug et la purge des sessions. Ce sont
// des réglages du SERVEUR, pas des entités de l'annuaire : aucun domaine ne les
// porte, et une délégation par domaine n'aurait rien à quoi s'appliquer.
//
// La lecture emprunte `read:log` plutôt qu'une clé neuve. Les deux répondent à
// « puis-je regarder comment ce serveur est réglé », et créer un
// `read:server` pour deux actions ajouterait une clé de plus à accorder dans
// toutes les permissions existantes — donc un droit qui manque partout jusqu'à
// ce que quelqu'un s'en aperçoive.

// EnregistrerActionsDuree ajoute la consultation et le réglage des durées.
func EnregistrerActionsDuree(r *Registre) {
	r.MustEnregistrer(Definition{
		Nom:     "settings.list",
		CleRBAC: permission.ActionReadLog,
		Portee:  PorteeGlobale,
		FiltreInutile: "un réglage de durée n'appartient à aucun domaine ; il n'y " +
			"a pas de périmètre selon lequel réduire la liste",
		Resume:   "liste les durées d'exploitation et leurs valeurs",
		Executer: listerDurees,
	})

	r.MustEnregistrer(Definition{
		Nom:      "settings.set",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "règle une durée d'exploitation",
		Executer: reglerDuree,
	})

	r.MustEnregistrer(Definition{
		Nom:      "settings.reset",
		CleRBAC:  permission.ActionWriteServer,
		Portee:   PorteeGlobale,
		Resume:   "ramène une durée à son défaut codé",
		Executer: reinitialiserDuree,
	})
}

// etatCourant et ecrireReglage sont remplaçables par les tests, comme
// recenserParc : la règle du TO-DO 161 s'éprouve sans base.
var (
	etatCourant   = reglages.EtatCourant
	ecrireReglage = reglages.Ecrire
)

func listerDurees(_ Appelant, _ Params) (Resultat, error) {
	etats := etatCourant()

	modifies, avertis := 0, 0
	for i, e := range etats {
		if !e.AuDefaut {
			modifies++
		}
		// Le même calcul qu'à la saisie, sur la valeur COURANTE (TO-DO 161) :
		// un parc où l'on remet un agent ancien après avoir monté la cadence
		// doit se voir ici, sans attendre le prochain « settings set ».
		if reglages.ExigeUnParcAJour(e.Cle, e.Valeur) {
			etats[i].Avertissement = avertissementDeCadence(e.Valeur)
			if etats[i].Avertissement != "" {
				avertis++
			}
		}
	}

	message := fmt.Sprintf("%d durée(s) d'exploitation, dont %d modifiée(s).",
		len(etats), modifies)
	if avertis > 0 {
		message += fmt.Sprintf(" %d avertissement(s).", avertis)
	}
	return Resultat{Message: message, Donnees: etats}, nil
}

// --- la cadence et le parc (TO-DO 161) ---------------------------------------

// ErrConfirmationRequise : l'action n'a RIEN fait, et le fera si on le lui
// confirme.
//
// Un type, et non un texte : la page des durées le reconnaît pour proposer un
// bouton « Confirmer » qui rejoue la même demande. La ligne de commande, elle,
// n'en a pas besoin — le motif dit quoi taper.
type ErrConfirmationRequise struct {
	Motif string
	// Rejouer porte les paramètres à renvoyer, « confirm » en plus.
	Rejouer Params
}

func (e *ErrConfirmationRequise) Error() string { return e.Motif }

// recenserParc lit le parc et le range par rapport à la version qui suit la
// cadence. Remplaçable par les tests : sans cela, éprouver la règle
// demanderait une base vivante.
var recenserParc = func() (parcversion.Bilan, error) {
	parc, err := dbclients.VersionsDuParc(database.GetDatabase())
	if err != nil {
		return parcversion.Bilan{}, err
	}
	return parcversion.Recenser(parc, reglages.VersionQuiSuitLaCadence), nil
}

// nombreDeNoms : « les cinq premières et le compte » — assez pour reconnaître
// un site ou un lot de postes, pas au point de noyer le message.
const nombreDeNoms = 5

// avertissementDeCadence rend ce que coûte une cadence au parc tel qu'il est,
// ou "" quand tout le parc la suit.
func avertissementDeCadence(minutes int) string {
	bilan, err := recenserParc()
	if err != nil {
		return "parc illisible, cadence non vérifiée : " + err.Error()
	}
	if bilan.ARisque() == 0 {
		return ""
	}
	return fmt.Sprintf("à %d min, %s ne suivent pas la cadence (antérieures à %s ou de "+
		"version inconnue) : elles ferment leur tunnel après 10 min sans trafic et se "+
		"reconnectent en boucle. Au plus %d min tant qu'elles ne sont pas à jour.",
		minutes, bilan.Resume(nombreDeNoms), reglages.VersionQuiSuitLaCadence,
		reglages.CadenceSurePourAgentsAnterieurs)
}

// confirme dit si la demande porte la confirmation explicite.
//
// « yes » seulement. La ligne de commande l'écrit pour « --confirm », la page
// pour son bouton : un mot que personne ne tape par hasard dans un champ.
func confirme(p Params) bool { return strings.EqualFold(p.Get("confirm"), "yes") }

// verifierLeParc tranche une valeur qui exige un parc à jour.
//
// Rend ("", nil) quand le parc suit ; (note, nil) quand il ne suit pas mais
// que la demande est confirmée — la note part dans le compte rendu ; et une
// ErrConfirmationRequise sinon.
//
// # Pas un refus
//
// Un parc peut vouloir assumer : quelques postes anciens qu'on remplace la
// semaine prochaine, un réseau où chaque réveil coûte. Le core prévient,
// nomme, et laisse décider — c'est l'esprit de la règle sur les versions
// (parcversion) : rien ne ferme une porte sur la foi d'une comparaison.
//
// # Un parc illisible demande aussi confirmation
//
// Ne pas pouvoir compter n'est pas compter zéro. Sinon une base momentanément
// injoignable laisserait passer sans un mot exactement le réglage qu'on voulait
// contrôler.
func verifierLeParc(a Appelant, p Params, cle string, valeur int) (string, error) {
	bilan, err := recenserParc()
	if err == nil && bilan.ARisque() == 0 {
		return "", nil
	}

	var constat string
	if err != nil {
		constat = fmt.Sprintf("le parc n'a pas pu être lu (%v) : rien ne dit que toutes les "+
			"machines suivent cette cadence", err)
	} else {
		constat = fmt.Sprintf("%s ne suivent pas cette cadence — antérieures à %s, ou de "+
			"version inconnue", bilan.Resume(nombreDeNoms), reglages.VersionQuiSuitLaCadence)
	}

	if confirme(p) {
		// Tracé : quand le parc se reconnectera en boucle, c'est cette ligne
		// qu'on cherchera, avec le nom de qui a choisi de l'assumer.
		logs.Write_Log("WARNING", fmt.Sprintf(
			"settings: %s porté à %d min par %s, CONFIRMÉ malgré l'avertissement : %s",
			cle, valeur, a.Username, constat))
		return fmt.Sprintf("Confirmé malgré l'avertissement : %s. Elles ferment leur tunnel "+
			"après 10 min sans trafic et se reconnecteront en boucle jusqu'à leur mise à jour.",
			constat), nil
	}

	return "", &ErrConfirmationRequise{
		Motif: fmt.Sprintf(
			"%s à %d min : RIEN n'a été changé.\n"+
				"%s.\n"+
				"Un agent antérieur à %s ferme son tunnel après 10 minutes sans trafic, "+
				"quelle que soit la cadence : au-delà de %d min, il se reconnecte en boucle.\n"+
				"Mettez ces machines à jour, ou confirmez : « %s ».",
			cle, valeur, upper1(constat), reglages.VersionQuiSuitLaCadence,
			reglages.CadenceSurePourAgentsAnterieurs,
			fmt.Sprintf("settings set %s %d --confirm", cle, valeur)),
		Rejouer: Params{"setting": cle, "value": strconv.Itoa(valeur), "confirm": "yes"},
	}
}

// upper1 met une majuscule à une phrase qui commence en minuscule.
func upper1(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func reglerDuree(a Appelant, p Params) (Resultat, error) {
	cle := p.Get("setting")
	if cle == "" {
		return Resultat{}, fmt.Errorf("clé de réglage requise. Connues : %s", reglages.Cles())
	}

	d, connue := reglages.DefinitionDe(cle)
	if !connue {
		// La liste des clés est donnée dans le refus. Sans elle, la seule façon
		// de retrouver le nom exact serait de relancer une autre commande — et
		// c'est le moment où l'on a le plus besoin de l'information.
		return Resultat{}, fmt.Errorf("réglage %q inconnu. Connues : %s", cle, reglages.Cles())
	}

	brut := p.Get("value")
	if brut == "" {
		return Resultat{}, fmt.Errorf("valeur requise, entre %d et %d %s", d.Min, d.Max, d.Unite)
	}
	valeur, err := strconv.Atoi(brut)
	if err != nil {
		return Resultat{}, fmt.Errorf("valeur %q invalide : ce n'est pas un nombre entier de %s", brut, d.Unite)
	}

	// Les bornes AVANT le parc : une valeur hors bornes doit être refusée pour
	// ce qu'elle est, pas faire l'objet d'une demande de confirmation qui
	// échouerait ensuite. Reglages.Ecrire les vérifie aussi ; c'est lui qui fait foi.
	if valeur < d.Min || valeur > d.Max {
		return Resultat{}, fmt.Errorf("%s doit être compris entre %d et %d %s",
			d.Cle, d.Min, d.Max, d.Unite)
	}

	// La cadence et le parc (TO-DO 161).
	note := ""
	if reglages.ExigeUnParcAJour(cle, valeur) {
		n, err := verifierLeParc(a, p, cle, valeur)
		if err != nil {
			return Resultat{}, err
		}
		note = n
	}

	ancienne := reglages.Valeur(cle)
	if err := ecrireReglage(cle, valeur, a.Username); err != nil {
		return Resultat{}, err
	}

	// Le compte rendu dit la valeur PRÉCÉDENTE et quand le changement prend
	// effet. Sans cela, un exploitant qui règle une cadence puis regarde les
	// journaux ne saurait pas s'il doit encore attendre.
	message := fmt.Sprintf(
		"%s : %d %s → %d %s.\nPrend effet au prochain tour de la boucle, sans redémarrage.\n%s",
		cle, ancienne, d.Unite, valeur, d.Unite, d.Consequence)
	if note != "" {
		message = note + "\n" + message
	}
	return Resultat{
		Message: message,
		Donnees: map[string]any{"setting": cle, "value": valeur, "previous": ancienne,
			"confirmed": note != ""},
	}, nil
}

func reinitialiserDuree(a Appelant, p Params) (Resultat, error) {
	cle := p.Get("setting")
	if cle == "" {
		return Resultat{}, fmt.Errorf("clé de réglage requise. Connues : %s", reglages.Cles())
	}
	d, connue := reglages.DefinitionDe(cle)
	if !connue {
		return Resultat{}, fmt.Errorf("réglage %q inconnu. Connues : %s", cle, reglages.Cles())
	}

	if err := reglages.Reinitialiser(cle, a.Username); err != nil {
		return Resultat{}, err
	}
	return Resultat{
		Message: fmt.Sprintf("%s ramené à son défaut : %d %s.", cle, d.Defaut, d.Unite),
		Donnees: map[string]any{"setting": cle, "value": d.Defaut},
	}, nil
}
