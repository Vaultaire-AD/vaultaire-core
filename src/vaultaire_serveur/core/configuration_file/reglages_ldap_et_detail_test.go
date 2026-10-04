package configuration_file

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ldapstorage "vaultaire/core/ldap/LDAP_Storage"
	"vaultaire/core/logs"
	"vaultaire/core/storage"
)

// Ce que le fichier de configuration règle depuis les TO-DO 145 et 152 : le
// détail du journal par sous-système, et les bornes de l'annuaire.
//
// # Ce que ces tests gardent
//
// Le CÂBLAGE. La règle de chaque réglage est éprouvée là où elle vit
// (core/logs, core/ldap/LDAP_Storage) ; ce qui peut encore se perdre, c'est la
// clé YAML — une étiquette mal écrite ne se voit ni à la compilation ni dans
// les tests de la règle, et le réglage se lirait dans le fichier sans rien
// régler. C'est arrivé à toute une section (TO-DO 99).

// etatDOrigine remet après le test tout ce que LoadConfig a pu poser.
func etatDOrigine(t *testing.T) {
	t.Helper()
	debug, tls := storage.Debug, ldapstorage.RequireTLSForBind
	bornes := []*int{&ldapstorage.MaxSearchEntries, &ldapstorage.MaxSearchDurationSeconds,
		&ldapstorage.MaxPageSize, &ldapstorage.MaxPagedSearchEntries, &ldapstorage.MaxPagedEntriesHeld,
		&ldapstorage.MaxPagedCursorsPerConnection, &ldapstorage.PagedCursorTTLSeconds}
	valeurs := make([]int, len(bornes))
	for i, b := range bornes {
		valeurs[i] = *b
	}
	bypass, sub := ldapstorage.MFABypass, ldapstorage.OneLevelSubtree
	mdp, admin := storage.Administrateur_Password, storage.Administrateur_Enable
	t.Cleanup(func() {
		storage.Debug, ldapstorage.RequireTLSForBind = debug, tls
		for i, b := range bornes {
			*b = valeurs[i]
		}
		ldapstorage.MFABypass, ldapstorage.OneLevelSubtree = bypass, sub
		storage.Administrateur_Password, storage.Administrateur_Enable = mdp, admin
		for _, s := range logs.SousSystemes() {
			logs.LaisserDetail(s)
		}
	})
	for _, s := range logs.SousSystemes() {
		logs.LaisserDetail(s)
	}
}

func charger(t *testing.T, yaml string) error {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "serveur_conf.yaml")
	if err := os.WriteFile(chemin, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadConfig(chemin)
}

func TestLeDetailParSousSystemeSeLitDansLeFichier(t *testing.T) {
	etatDOrigine(t)

	err := charger(t, `
debug:
  debug: true
  detail:
    ldap: off
    gpo: trace
`)
	if err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	if !storage.Debug {
		t.Error("debug.debug n'a pas été lu")
	}
	if d, propre := logs.DetailRegle(logs.SousLDAP); !propre || d != logs.DetailCoupe {
		t.Errorf("ldap = %v (propre=%v), attendu off", d, propre)
	}
	if d, propre := logs.DetailRegle(logs.SousGPO); !propre || d != logs.DetailTrace {
		t.Errorf("gpo = %v (propre=%v), attendu trace", d, propre)
	}
	if _, propre := logs.DetailRegle(logs.SousDucky); propre {
		t.Error("ducky porte un réglage propre que le fichier ne lui donne pas")
	}
}

// Le fichier décrit l'état VOULU : un sous-système qui n'y figure pas n'a pas
// de réglage propre, quoi qu'il ait porté avant.
func TestUnSousSystemeAbsentDuFichierNAPasDeReglage(t *testing.T) {
	etatDOrigine(t)
	logs.ReglerDetail(logs.SousBase, logs.DetailTrace)

	if err := charger(t, "debug:\n  detail:\n    ldap: debug\n"); err != nil {
		t.Fatal(err)
	}
	if _, propre := logs.DetailRegle(logs.SousBase); propre {
		t.Fatal("base garde un réglage que le fichier ne porte pas")
	}
}

// Une faute de frappe ARRÊTE le démarrage, en disant quoi écrire. Ignorée, elle
// laisserait le détail éteint pendant qu'on cherche pourquoi la panne n'écrit
// rien.
func TestUnDetailMalEcritArreteLeDemarrage(t *testing.T) {
	for nom, c := range map[string]struct{ yaml, attendu string }{
		"sous-système inconnu": {"debug:\n  detail:\n    ldpa: trace\n", "ldap, ducky, gpo, base"},
		"niveau inconnu":       {"debug:\n  detail:\n    ldap: verbeux\n", "off, debug, trace"},
	} {
		t.Run(nom, func(t *testing.T) {
			etatDOrigine(t)
			err := charger(t, c.yaml)
			var valeur *ErreurDeValeur
			if !errors.As(err, &valeur) {
				t.Fatalf("err = %v : attendu une ErreurDeValeur — une valeur refusée "+
					"n'est pas un fichier introuvable", err)
			}
			if !strings.Contains(err.Error(), c.attendu) || !strings.Contains(err.Error(), "debug.detail") {
				t.Errorf("le refus ne dit pas quoi corriger : %v", err)
			}
			for _, s := range logs.SousSystemes() {
				if _, propre := logs.DetailRegle(s); propre {
					t.Errorf("%s réglé par un fichier refusé", s)
				}
			}
		})
	}
}

func TestLesBornesLDAPSeLisentDansLeFichier(t *testing.T) {
	etatDOrigine(t)

	err := charger(t, `
ldap:
  require_tls_for_bind: true
  limites:
    max_search_entries: 5000
    max_page_size: 250
    paged_cursor_ttl_seconds: 120
`)
	if err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	if !ldapstorage.RequireTLSForBind {
		t.Error("ldap.require_tls_for_bind n'a pas été lu")
	}
	if ldapstorage.MaxSearchEntries != 5000 || ldapstorage.MaxPageSize != 250 || ldapstorage.PagedCursorTTLSeconds != 120 {
		t.Errorf("bornes lues : %d, %d, %d — attendu 5000, 250, 120",
			ldapstorage.MaxSearchEntries, ldapstorage.MaxPageSize, ldapstorage.PagedCursorTTLSeconds)
	}
}

// `require_tls_for_bind` absent vaut FAUX, et le redevient : le retirer du
// fichier doit rouvrir le port en clair, pas laisser l'ancien réglage en place.
func TestRequireTLSAbsentVautFaux(t *testing.T) {
	etatDOrigine(t)
	ldapstorage.RequireTLSForBind = true

	if err := charger(t, "ldap:\n  ldap_enable: true\n"); err != nil {
		t.Fatal(err)
	}
	if ldapstorage.RequireTLSForBind {
		t.Fatal("require_tls_for_bind reste actif alors que le fichier ne le porte plus")
	}
}

// Une borne refusée ARRÊTE le démarrage — voir ldapstorage.AppliquerLimites.
func TestUneBorneRefuseeArreteLeDemarrage(t *testing.T) {
	for nom, yaml := range map[string]string{
		"zéro, qui désactiverait la borne": "ldap:\n  limites:\n    max_search_entries: 0\n",
		"clé mal orthographiée":            "ldap:\n  limites:\n    max_page_sizes: 500\n",
	} {
		t.Run(nom, func(t *testing.T) {
			etatDOrigine(t)
			avant := ldapstorage.MaxSearchEntries

			err := charger(t, yaml)
			var valeur *ErreurDeValeur
			if !errors.As(err, &valeur) || !strings.Contains(err.Error(), "ldap.limites") {
				t.Fatalf("err = %v : attendu un refus nommant ldap.limites", err)
			}
			if ldapstorage.MaxSearchEntries != avant {
				t.Errorf("max_search_entries vaut %d après un fichier refusé", ldapstorage.MaxSearchEntries)
			}
		})
	}
}

// LE FICHIER LIVRÉ se charge, et laisse les bornes à leurs valeurs par défaut.
//
// Il les écrit toutes, en clair, pour qu'on sache qu'elles existent. Si l'une
// de ses valeurs sortait de l'intervalle admis — ou si une clé changeait de nom
// sans que le fichier suive —, toute installation neuve refuserait de démarrer.
func TestLeFichierLivrePorteLesBornesParDefaut(t *testing.T) {
	etatDOrigine(t)
	defauts := ldapstorage.LimitesEnVigueur()

	contenu, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deployments", "configs", "serveur_conf.yaml"))
	if err != nil {
		// Le fichier est dans le dépôt, pas dans le module : un module extrait
		// seul ne l'a pas. Même règle que le test voisin du point 99.
		t.Skipf("fichier livré introuvable (%v) — vérification ignorée", err)
	}
	if err := charger(t, string(contenu)); err != nil {
		t.Fatalf("le fichier livré est refusé : %v", err)
	}
	if got := ldapstorage.LimitesEnVigueur(); got != defauts {
		t.Errorf("le fichier livré change les bornes :\n  livré  %s\n  défaut %s", got, defauts)
	}
	for _, cle := range ldapstorage.ClesDesLimites() {
		if !strings.Contains(string(contenu), cle+":") {
			t.Errorf("le fichier livré ne mentionne pas ldap.limites.%s : "+
				"une borne qu'on ne voit pas dans le fichier est une borne qu'on ne règle pas", cle)
		}
	}
	if ldapstorage.RequireTLSForBind {
		t.Error("le fichier livré active require_tls_for_bind : il couperait à la mise à " +
			"jour tout client configuré sur le port 389")
	}
	if logs.UnDetailEstActif() {
		t.Error("le fichier livré active un détail de journal")
	}
}
