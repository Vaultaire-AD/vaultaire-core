package proxiesconnus

import (
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	dbschema "vaultaire/core/database/db_schema"
)

// La confiance des proxies suit l'adresse VUE par le core (TO-DO 184).

func TestLAdresseVueLEmporteEtLExpositionNeCompteJamais(t *testing.T) {
	cas := []struct{ declaree, vue, attendu string }{
		{"172.18.0.4", "172.19.0.1", "172.19.0.1"}, // derrière un NAT docker : la passerelle
		{"10.0.0.5", "", "10.0.0.5"},               // pas encore revenu battre : la déclarée
		{"10.0.0.5", "::ffff:10.0.0.6", "10.0.0.6"},
		{"pas-une-ip", "", ""},
	}
	for _, c := range cas {
		if got := AdresseDeConfiance(c.declaree, c.vue); got != c.attendu {
			t.Errorf("déclarée %q, vue %q : %q, attendu %q", c.declaree, c.vue, got, c.attendu)
		}
	}
}

func TestUneSessionDeProxySurCeCoreSuffit(t *testing.T) {
	ancien := sourcesVivantes
	t.Cleanup(func() { sourcesVivantes = ancien; Remplacer(nil); poserProprietaires(nil) })
	sourcesVivantes = func(p string) []string {
		if p == "owner-proxy" {
			return []string{"192.0.2.7"}
		}
		return nil
	}
	Remplacer([]string{"10.0.0.5"})
	poserProprietaires([]string{"owner-proxy"})

	if !EstUnProxy("10.0.0.5") {
		t.Error("l'adresse lue en base n'est plus de confiance")
	}
	if !EstUnProxy("192.0.2.7") {
		t.Error("la source d'une session de proxy sur ce core n'est pas de confiance")
	}
	if EstUnProxy("192.0.2.8") {
		t.Error("une adresse quelconque est de confiance")
	}
}

func TestEnBaseLExpositionNEstPlusDeConfiance(t *testing.T) {
	dsn := os.Getenv("VAULTAIRE_TEST_DSN")
	if dsn == "" {
		t.Skip("VAULTAIRE_TEST_DSN absent : pas de base de test MariaDB")
	}
	base, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	dbschema.Create_DataBase(base)
	_, _ = base.Exec(`UPDATE cluster_nodes SET status = 'offline' WHERE role = 'proxy'`)

	suffixe := fmt.Sprint(time.Now().UnixNano())
	inserer := func(nom, declaree, vue, publique string) {
		t.Helper()
		if _, err := base.Exec(`INSERT INTO cluster_nodes (hostname, fqdn, ip_address, role, status,
			version_code, owner_client_id, last_heartbeat, adresse_vue, adresse_publique)
			VALUES (?, ?, ?, 'proxy', 'online', 't', ?, NOW(), ?, ?)`,
			nom, nom, declaree, "o-"+nom, vue, publique); err != nil {
			t.Fatal(err)
		}
	}
	inserer("nat-"+suffixe, "172.18.0.4", "172.19.0.1", "203.0.113.10")
	inserer("neuf-"+suffixe, "10.0.0.5", "", "203.0.113.11")

	liste, qui, err := lire(base)
	if err != nil {
		t.Fatal(err)
	}
	vus := map[string]bool{}
	for _, a := range liste {
		vus[a] = true
	}
	if !vus["172.19.0.1"] || !vus["10.0.0.5"] {
		t.Errorf("liste de confiance %v : il manque l'adresse vue ou la déclarée de repli", liste)
	}
	for _, interdite := range []string{"203.0.113.10", "203.0.113.11", "172.18.0.4"} {
		if vus[interdite] {
			t.Errorf("%s est de confiance : adresse d'exposition, ou déclarée alors qu'une vue est connue", interdite)
		}
	}
	if len(qui) < 2 {
		t.Errorf("identifiants des proxies : %v", qui)
	}
}
