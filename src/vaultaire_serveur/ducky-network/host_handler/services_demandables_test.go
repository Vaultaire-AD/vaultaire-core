package hosthandler

import (
	"strings"
	"testing"

	"vaultaire/core/clienttype"
	"vaultaire/core/storage"
)

// TO-DO 114 : l'agent a la 04_15, mais pour les Nexus seulement.
func TestTypeDemandable(t *testing.T) {
	cas := []struct {
		demandeur, typ string
		attendu        bool
	}{
		{clienttype.Client, clienttype.Nexus, true},
		{clienttype.Client, clienttype.Web, false},
		{clienttype.Client, clienttype.Proxy, false},
		{clienttype.Client, "n'importe", false},
		// Le proxy garde ce qu'il avait : tout type, filtré ensuite par
		// typeDeServiceRelayable.
		{clienttype.Proxy, clienttype.Nexus, true},
		{clienttype.Proxy, clienttype.Web, true},
		// Une session sans type lié n'obtient rien.
		{"", clienttype.Nexus, false},
	}
	for _, c := range cas {
		if got := TypeDemandable(c.demandeur, c.typ); got != c.attendu {
			t.Errorf("TypeDemandable(%q, %q) = %v", c.demandeur, c.typ, got)
		}
	}
}

// Un agent qui demande un autre type reçoit une liste vide, sans que la base
// soit seulement lue — db nil le prouve : servicesEnLigne échouerait.
func TestUnAgentNObtientQueLesNexus(t *testing.T) {
	trame := storage.Trames_struct_client{ClientSoftwareID: "poste-1", Message_Order: []string{"04", "15"}}
	session := &storage.DuckySession{BoundClientType: clienttype.Client}
	rep, err := handleListServices(nil, trame, clienttype.Web, session)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rep, clienttype.Web+"\n0") {
		t.Errorf("réponse : %q", rep)
	}
}
