package dbrevocation

import (
	"strings"
	"testing"

	"vaultaire/core/clienttype"
	"vaultaire/core/revocation"
)

// TO-DO 167 : seules les machines qui savent appliquer un ordre sont visées.

func TestSeulsLesTypesQuiAcquittentSontVises(t *testing.T) {
	types := clienttype.TypesQuiAcquittent()
	if strings.Join(types, ",") != clienttype.Client {
		t.Fatalf("types qui acquittent = %v, attendu le seul agent (%s)", types, clienttype.Client)
	}

	cibles := []string{"PC-01", "proxy-1", "NEXUS-1", "inconnue", "web-1"}
	connus := map[string]string{
		"pc-01":   clienttype.Client,
		"proxy-1": clienttype.Proxy,
		"nexus-1": clienttype.Nexus,
		"web-1":   clienttype.Web,
	}
	gardees, ecartees := GarderLesRevocables(cibles, connus)
	if strings.Join(gardees, ",") != "PC-01,inconnue" {
		t.Errorf("gardées = %v : l'agent, et la machine inconnue (on ne décide pas à sa place)", gardees)
	}
	if strings.Join(ecartees, ",") != "proxy-1 (vaultaire_proxy),NEXUS-1 (vaultaire_nexus),web-1 (vaultaire_web)" {
		t.Errorf("écartées = %v", ecartees)
	}
	// Aucune lecture de type : rien n'est écarté.
	if g, e := GarderLesRevocables(cibles, map[string]string{}); len(g) != len(cibles) || len(e) != 0 {
		t.Errorf("sans types connus, %d gardées / %d écartées", len(g), len(e))
	}
}

func TestNonPrisEnChargeNiAFaireNiRegle(t *testing.T) {
	s := revocation.StatusNonPrisEnCharge
	if s.ARejouer() {
		t.Error("un ordre « non pris en charge » serait rejoué pour toujours")
	}
	if s.Libelle() != "non pris en charge" {
		t.Errorf("libellé = %q", s.Libelle())
	}
	// Le rejeu en SQL dit la même chose que ARejouer.
	if strings.Contains(sqlARejouer, string(s)) {
		t.Error("sqlARejouer rejoue les cibles non prises en charge")
	}
	if len(string(s)) > 16 {
		t.Errorf("%q ne tient pas dans status VARCHAR(16)", s)
	}

	cibles := []TargetRecord{
		cible("PC-01", revocation.StatusAcked, 1, "applied"),
		cible("WIN-01", revocation.StatusNonPrisEnCharge, 1, "agent Windows V1 : révocation non appliquée"),
		cible("PC-02", revocation.StatusPending, 0, ""),
	}
	TrierCibles(cibles)
	if cibles[0].ComputeurID != "PC-02" || cibles[1].ComputeurID != "WIN-01" {
		t.Errorf("ordre : %s, %s, %s — attendu ce qui attend, puis le non pris en charge, puis l'appliqué",
			cibles[0].ComputeurID, cibles[1].ComputeurID, cibles[2].ComputeurID)
	}
	d := Compter(cibles)
	if d.NonPrisEnCharge != 1 || d.ResteAFaire() != 1 || d.Total() != 3 {
		t.Errorf("décompte = %+v (reste %d, total %d)", d, d.ResteAFaire(), d.Total())
	}
	if !strings.Contains(d.Lisible(), "1 non pris en charge par le client") {
		t.Errorf("décompte lisible : %q", d.Lisible())
	}
	if c := cibles[1].Commentaire(); !strings.Contains(c, "agent Windows V1") || !strings.Contains(c, "plus remis") {
		t.Errorf("commentaire : %q", c)
	}
}
