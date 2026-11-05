package clusterstorage

import (
	"fmt"
	"time"
)

// Ce qu'un CORE publie de ses sessions avec son battement — TO-DO 148.
//
// Le pendant de MetriquesRelais, pour l'autre genre de nœud : un proxy relaie
// des connexions, un core porte des sessions. Les étiquettes JSON sont écrites
// dans la colonne `extra` de `proxy_metrics`, sous le type « sessions » ; un
// champ absent vaut zéro, comme pour les relais.
//
// Mesure DÉCLARATIVE : elle s'affiche, elle n'ordonne pas la liste servie aux
// agents (même règle qu'au TO-DO 108). Un core chargé n'est pas écarté pour
// autant ; on le voit, on décide.
type MetriquesSessions struct {
	Machines int64 `json:"machines"`
	Tunnels  int64 `json:"tunnels"`
	Comptes  int64 `json:"comptes"`
	Poignees int64 `json:"poignees"`

	// Mesure est l'heure d'enregistrement de la ligne : depuis quand on
	// regarde ces chiffres.
	Mesure time.Time `json:"-"`
}

// Total rend le nombre de sessions tenues, toutes natures confondues.
func (m MetriquesSessions) Total() int64 { return m.Tunnels + m.Comptes + m.Poignees }

// Lisible rend la forme courte de la liste : « 42 m · 3 c », « · 1 p » en plus
// s'il y a des poignées de main en cours.
//
// Une MÉTHODE pour que le gabarit web et la ligne de commande affichent la
// même chose — deux formatages auraient divergé.
func (m MetriquesSessions) Lisible() string {
	s := fmt.Sprintf("%d m · %d c", m.Machines, m.Comptes)
	if m.Poignees > 0 {
		s += fmt.Sprintf(" · %d p", m.Poignees)
	}
	return s
}
