package clusterstorage

import "time"

// EtatMaintenance : la maintenance d'un nœud et la purge de ses sessions —
// TO-DO 147.
//
// Lu à part de Node, comme les mesures : les requêtes qui chargent les nœuds
// sont nombreuses, et y ajouter huit colonnes les aurait toutes touchées pour
// une information que seules les vues affichent. La décision, elle, vit dans
// les requêtes des LISTES (04_04, 04_16), qui filtrent sur la colonne.
type EtatMaintenance struct {
	Active bool
	Par    string
	Depuis time.Time

	// La dernière purge demandée, et où elle en est. PurgeDemandee nulle :
	// aucune purge n'a jamais été demandée.
	PurgeDemandee time.Time
	PurgePar      string
	Etalement     int // secondes
	PurgeTerminee time.Time
	Fermees       int
}

// PurgeEnCours : une purge est demandée et le core visé n'a pas encore écrit
// sa fin. Comparée à la DEMANDE, et non à la seule présence d'une date de fin :
// une seconde purge demandée après la première doit se lire « en cours ».
func (e EtatMaintenance) PurgeEnCours() bool {
	return !e.PurgeDemandee.IsZero() &&
		(e.PurgeTerminee.IsZero() || e.PurgeTerminee.Before(e.PurgeDemandee))
}

// PurgeFaite : la dernière purge demandée est terminée.
func (e EtatMaintenance) PurgeFaite() bool {
	return !e.PurgeDemandee.IsZero() && !e.PurgeEnCours()
}
