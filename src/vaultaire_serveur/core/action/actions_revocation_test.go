package action

import (
	"strings"
	"testing"

	dbrevocation "vaultaire/core/database/db_revocation"
	"vaultaire/core/revocation"
)

// perimetreDEssai : « cet appelant voit paris, pas lyon ». Les machines sont
// rangées dans un domaine d'après leur nom.
type perimetreDEssai struct {
	global   bool
	domaines map[string]bool
}

func (p perimetreDEssai) Global() bool { return p.global }

func (p perimetreDEssai) AutoriseUnDes(domaines []string) bool {
	if p.global {
		return true
	}
	for _, d := range domaines {
		if p.domaines[d] {
			return true
		}
	}
	return false
}

func (perimetreDEssai) DomainesDe(genre GenreEntite, id string) []string {
	if genre != EntiteClient {
		return nil
	}
	switch {
	case strings.HasPrefix(id, "PAR-"):
		return []string{"paris"}
	case strings.HasPrefix(id, "LYO-"):
		return []string{"lyon"}
	}
	return nil // machine sans domaine : visible du seul périmètre global
}

func suiviDEssai() dbrevocation.Suivi {
	c := func(nom string, s revocation.TargetStatus) dbrevocation.TargetRecord {
		return dbrevocation.TargetRecord{ComputeurID: nom, Status: s}
	}
	return dbrevocation.Suivi{
		Username: "alice", Verrouille: true,
		Ordres: []dbrevocation.OrdreSuivi{
			{Record: dbrevocation.Record{ID: 12, Total: 4, Pending: 2}, Cibles: []dbrevocation.TargetRecord{
				c("LYO-07", revocation.StatusFailed), c("PAR-03", revocation.StatusPending),
				c("PAR-01", revocation.StatusAcked), c("SANS-DOMAINE", revocation.StatusAcked),
			}},
			{Record: dbrevocation.Record{ID: 9, Total: 1}, Cibles: []dbrevocation.TargetRecord{
				c("LYO-07", revocation.StatusAcked),
			}},
		},
	}
}

func machinesDe(o dbrevocation.OrdreSuivi) string {
	var noms []string
	for _, c := range o.Cibles {
		noms = append(noms, c.ComputeurID)
	}
	return strings.Join(noms, ",")
}

// Un délégué de paris qui regarde un compte à cheval sur paris et lyon ne doit
// pas apprendre le nom d'un poste de lyon — TO-DO 164. Les machines masquées
// sont COMPTÉES, ordre par ordre : une liste tronquée en silence se lirait
// comme « l'ordre est réglé ».
func TestLeSuiviEstReduitAuPerimetreEtLeDit(t *testing.T) {
	origine := suiviDEssai()
	rendu, masquees := filtrerSuiviRevocation(origine, perimetreDEssai{domaines: map[string]bool{"paris": true}})
	suivi, ok := rendu.(dbrevocation.Suivi)
	if !ok {
		t.Fatalf("le filtre a changé le type des données : %T", rendu)
	}
	if masquees != 3 {
		t.Errorf("%d cible(s) annoncée(s) masquée(s), attendu 3 (deux à lyon, une sans domaine)", masquees)
	}
	if got := machinesDe(suivi.Ordres[0]); got != "PAR-03,PAR-01" {
		t.Errorf("ordre 12 vu de paris : %s — attendu les seules machines de paris, dans l'ordre", got)
	}
	if suivi.Ordres[0].Masquees != 2 || suivi.Ordres[1].Masquees != 1 {
		t.Errorf("machines masquées par ordre : %d et %d, attendu 2 et 1", suivi.Ordres[0].Masquees, suivi.Ordres[1].Masquees)
	}
	if len(suivi.Ordres[1].Cibles) != 0 {
		t.Errorf("l'ordre 9 ne visait que lyon : %s reste visible", machinesDe(suivi.Ordres[1]))
	}
	// Le total d'un ordre ne dépend pas de qui le regarde, et l'état du compte
	// non plus.
	if suivi.Ordres[0].Total != 4 || suivi.Ordres[0].Pending != 2 || !suivi.Verrouille {
		t.Errorf("le filtre a touché au total de l'ordre ou à l'état du compte : %+v", suivi.Ordres[0].Record)
	}
	// Le filtre travaille sur une copie.
	if got := machinesDe(origine.Ordres[0]); got != "LYO-07,PAR-03,PAR-01,SANS-DOMAINE" || origine.Ordres[0].Masquees != 0 {
		t.Errorf("le filtre a modifié les données rendues par l'action : %s", got)
	}
}

func TestUnPerimetreGlobalVoitToutLeSuivi(t *testing.T) {
	rendu, masquees := filtrerSuiviRevocation(suiviDEssai(), perimetreDEssai{global: true})
	suivi := rendu.(dbrevocation.Suivi)
	if masquees != 0 || len(suivi.Ordres[0].Cibles) != 4 || suivi.Ordres[0].Masquees != 0 {
		t.Fatalf("périmètre global : %d masquée(s), %d cible(s)", masquees, len(suivi.Ordres[0].Cibles))
	}
}

func TestLeFiltreDuSuiviLaisseCeQuIlNeConnaitPas(t *testing.T) {
	if rendu, masquees := filtrerSuiviRevocation("autre chose", perimetreDEssai{}); rendu != "autre chose" || masquees != 0 {
		t.Fatalf("le filtre a touché à des données d'un autre type : %v, %d", rendu, masquees)
	}
}

// L'action est une LECTURE : sa clé ne commence pas par « write: », sans quoi
// chaque ouverture de la fiche d'un compte s'écrirait au journal comme une
// écriture — dans le journal où l'on cherche qui a coupé qui.
func TestLeSuiviEstUneLecture(t *testing.T) {
	r := NouveauRegistre()
	EnregistrerActionsRevocation(r)
	d, ok := r.Definition("revocation.get_status")
	if !ok {
		t.Fatal("revocation.get_status n'est pas enregistrée")
	}
	if estEcriture(d) {
		t.Errorf("revocation.get_status est gardée par %q : elle serait tracée comme une écriture", d.CleRBAC)
	}
	if d.CleRBAC != "read:status:user" || !d.UnDomaineSuffit || d.Filtre == nil {
		t.Errorf("revocation.get_status : clé %q, un domaine suffit = %v, filtre présent = %v",
			d.CleRBAC, d.UnDomaineSuffit, d.Filtre != nil)
	}
}
