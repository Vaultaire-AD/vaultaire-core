package configuration_file

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vaultaire/core/storage"
)

func table(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

// sauver remet les variables globales touchées par ces tests en l'état.
func sauver(t *testing.T) {
	t.Helper()
	db, pw, host, port, admin, ldap, data, dns := storage.Database_username, storage.Database_password,
		storage.Database_iPDatabase, storage.Database_portDatabase, storage.Administrateur_Password,
		storage.Ldap_Port, storage.Client_Conf_path, storage.Dns_Port
	names := storage.Ldaps_TLS_DNSNames
	t.Cleanup(func() {
		storage.Database_username, storage.Database_password, storage.Database_iPDatabase,
			storage.Database_portDatabase, storage.Administrateur_Password, storage.Ldap_Port,
			storage.Client_Conf_path, storage.Dns_Port = db, pw, host, port, admin, ldap, data, dns
		storage.Ldaps_TLS_DNSNames = names
	})
}

func TestLEnvironnementLEmporteSurLeFichier(t *testing.T) {
	sauver(t)
	storage.Database_iPDatabase = "depuis-le-fichier"
	err := AppliquerEnvironnement(table(map[string]string{
		"VAULTAIRE_DB_HOST":             "mariadb.vaultaire.svc",
		"VAULTAIRE_DB_PORT":             "3307",
		"VAULTAIRE_LDAP_PORT":           "3389",
		"VAULTAIRE_DNS_PORT":            "5353",
		"VAULTAIRE_DATA_DIR":            "/var/lib/vaultaire",
		"VAULTAIRE_LDAPS_TLS_DNS_NAMES": " ldap.acme.lan, vaultaire-ldap ,",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if storage.Database_iPDatabase != "mariadb.vaultaire.svc" || storage.Database_portDatabase != "3307" {
		t.Errorf("base : %s:%s", storage.Database_iPDatabase, storage.Database_portDatabase)
	}
	if storage.Ldap_Port != 3389 || storage.Dns_Port != 5353 {
		t.Errorf("ports : ldap %d dns %d", storage.Ldap_Port, storage.Dns_Port)
	}
	if storage.Client_Conf_path != "/var/lib/vaultaire/" {
		t.Errorf("répertoire sans / final : %q (le code concatène « .ssh/ »)", storage.Client_Conf_path)
	}
	if strings.Join(storage.Ldaps_TLS_DNSNames, "|") != "ldap.acme.lan|vaultaire-ldap" {
		t.Errorf("SAN : %q", storage.Ldaps_TLS_DNSNames)
	}
}

func TestUnSecretSeLitDansUnFichier(t *testing.T) {
	sauver(t)
	f := filepath.Join(t.TempDir(), "db-password")
	if err := os.WriteFile(f, []byte("s3cret avec espace\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AppliquerEnvironnement(table(map[string]string{"VAULTAIRE_DB_PASSWORD_FILE": f})); err != nil {
		t.Fatal(err)
	}
	if storage.Database_password != "s3cret avec espace" {
		t.Errorf("mot de passe %q : la fin de ligne doit être retirée, rien d'autre", storage.Database_password)
	}
}

func TestLesErreursSontRefuseesEtNommees(t *testing.T) {
	sauver(t)
	cas := map[string]map[string]string{
		"vide":             {"VAULTAIRE_DB_PASSWORD": ""},
		"les deux":         {"VAULTAIRE_DB_PASSWORD": "a", "VAULTAIRE_DB_PASSWORD_FILE": "/x"},
		"fichier absent":   {"VAULTAIRE_ADMIN_PASSWORD_FILE": "/nulle/part"},
		"port":             {"VAULTAIRE_LDAP_PORT": "70000"},
		"booleen":          {"VAULTAIRE_DNS_ENABLE": "peut-etre"},
		"_FILE non secret": {"VAULTAIRE_DB_HOST_FILE": "/x", "VAULTAIRE_DB_HOST": ""},
	}
	for nom, env := range cas {
		err := AppliquerEnvironnement(table(env))
		if err == nil {
			t.Errorf("%s : accepté", nom)
			continue
		}
		for k := range env {
			if strings.HasSuffix(k, "_FILE") && nom == "_FILE non secret" {
				continue
			}
			if !strings.Contains(err.Error(), strings.TrimSuffix(k, "_FILE")) {
				t.Errorf("%s : l'erreur ne nomme pas %s : %v", nom, k, err)
			}
		}
	}
}

// Une variable inconnue de la table n'a aucun effet : seuls les noms
// documentés sont lus.
func TestSansVariableRienNeChange(t *testing.T) {
	sauver(t)
	storage.Database_password = "fichier"
	if err := AppliquerEnvironnement(table(nil)); err != nil {
		t.Fatal(err)
	}
	if storage.Database_password != "fichier" {
		t.Error("la valeur du fichier a été remplacée sans variable posée")
	}
}
