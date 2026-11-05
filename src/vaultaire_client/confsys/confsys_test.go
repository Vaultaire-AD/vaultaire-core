package confsys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// LE test du point : les scripts d'installation et l'agent écrivent la même
// chose. Pour chaque famille, avec et sans GDM, le script est joué à blanc sur
// un poste neuf ; puis, pour chaque fichier tenu, l'agent produit le sien à
// partir de l'ORIGINAL — les octets doivent être les mêmes. Et sur le poste
// installé, un passage ne trouve rien à faire.
func TestLesScriptsEtLAgentProduisentLaMemeChose(t *testing.T) {
	for _, famille := range []string{"rocky", "debian"} {
		for _, gdm := range []bool{false, true} {
			t.Run(famille+map[bool]string{true: "+gdm", false: ""}[gdm], func(t *testing.T) {
				p := nouveauPoste(t, famille, gdm)
				p.installer()
				regles, err := Regles(famille, gdm)
				if err != nil {
					t.Fatal(err)
				}
				vus := 0
				for _, r := range regles {
					attendu, err := r.Produire(p.origine[r.Rel])
					if err != nil {
						t.Fatalf("%s : %v", r.Nom, err)
					}
					if got := p.lire(r.Rel); got != attendu {
						t.Errorf("%s : le script et l'agent divergent.\n--- script ---\n%s--- agent ---\n%s", r.Nom, got, attendu)
					}
					if v := LireVersion(attendu); v != r.Version {
						t.Errorf("%s : marqueur v%d, règle v%d — monter les deux ensemble", r.Nom, v, r.Version)
					}
					vus++
				}
				if vus != len(p.tenus()) {
					t.Errorf("%d règles, %d fichiers tenus attendus", vus, len(p.tenus()))
				}
				f := &fauxSysteme{}
				r := Reconcilier(p.env(f))
				if r.Etat != EtatConforme || len(f.ecritures()) != 0 {
					t.Errorf("après installation : %s (%s), appels %v", r.Etat, r.Motif, f.ecritures())
				}
			})
		}
	}
}

// Une machine installée AVANT le 117 : les mêmes fichiers, sans marqueurs.
// Un passage les remet exactement dans l'état d'une installation neuve,
// sauvegarde chacun, valide sshd_config, recharge sshd et dconf.
func TestUneMachineInstalleeAvantLe117(t *testing.T) {
	for _, famille := range []string{"rocky", "debian"} {
		t.Run(famille, func(t *testing.T) {
			p := nouveauPoste(t, famille, true)
			p.installer()
			neuve := map[string]string{}
			for _, rel := range p.tenus() {
				neuve[rel] = p.lire(rel)
				p.ecrire(rel, sansMarqueurs(neuve[rel]))
			}
			f := &fauxSysteme{}
			r := Reconcilier(p.env(f))
			if r.Etat != EtatReconciliee || !strings.Contains(r.Motif, "ssh/sshd_config v0→v1") {
				t.Fatalf("%s : %s", r.Etat, r.Motif)
			}
			for _, rel := range p.tenus() {
				if got := p.lire(rel); got != neuve[rel] {
					t.Errorf("%s :\n%s\nattendu\n%s", rel, got, neuve[rel])
				}
			}
			// Les sauvegardes : à côté du fichier, sauf dconf.
			bak := p.chemin("etc/pam.d/sshd.vaultaire-bak-20261018-121530")
			if b, err := os.ReadFile(bak); err != nil || string(b) != sansMarqueurs(neuve["etc/pam.d/sshd"]) {
				t.Errorf("sauvegarde de pam.d/sshd : %v", err)
			}
			if l, _ := filepath.Glob(p.chemin("etc/dconf/db/gdm.d/*bak*")); len(l) != 0 {
				t.Errorf("sauvegarde dans gdm.d, que dconf compilerait : %v", l)
			}
			if _, err := os.Stat(p.chemin("var/lib/vaultaire/confsys/sauvegardes/10-vaultaire-userlist.vaultaire-bak-20261018-121530")); err != nil {
				t.Errorf("sauvegarde dconf : %v", err)
			}
			for _, attendu := range []string{"sshd -t -f " + p.chemin("etc/ssh/.sshd_config.vaultaire-"),
				"systemctl try-reload-or-restart " + ServiceSSH(famille) + ".service", "dconf update", "restorecon -F"} {
				if !f.a(attendu) {
					t.Errorf("%q non joué : %v", attendu, f.appels)
				}
			}
			// Aucun fichier temporaire ne traîne.
			for _, d := range []string{"etc/pam.d", "etc/ssh", "etc", "etc/dconf/db/gdm.d"} {
				if l, _ := filepath.Glob(p.chemin(d + "/.*vaultaire*")); len(l) != 0 {
					t.Errorf("temporaires dans %s : %v", d, l)
				}
			}
			// Et un second passage ne fait plus rien.
			f2 := &fauxSysteme{}
			if r := Reconcilier(p.env(f2)); r.Etat != EtatConforme || len(f2.ecritures()) != 0 {
				t.Errorf("second passage : %s %v", r.Etat, f2.ecritures())
			}
		})
	}
}

// Le cas qui rend le point urgent (TO-DO 95) : une machine d'avant la 2.2,
// dont sshd_config n'a pas KbdInteractiveAuthentication — l'invite du second
// facteur n'y apparaît jamais, en silence.
func TestAvantLa22LeSecondFacteurRevient(t *testing.T) {
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	vieux := strings.ReplaceAll(sansMarqueurs(p.lire("etc/ssh/sshd_config")), "KbdInteractiveAuthentication yes\n", "")
	vieux = strings.ReplaceAll(vieux, "ChallengeResponseAuthentication yes\n", "")
	p.ecrire("etc/ssh/sshd_config", "KbdInteractiveAuthentication no\n"+vieux)
	r := Reconcilier(p.env(&fauxSysteme{}))
	if r.Etat != EtatReconciliee {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	c := p.lire("etc/ssh/sshd_config")
	if strings.Count(c, "KbdInteractiveAuthentication") != 1 || !strings.Contains(c, "KbdInteractiveAuthentication yes\n") {
		t.Errorf("sshd_config :\n%s", c)
	}
	// Les autres directives de l'administrateur sont gardées.
	if !strings.Contains(c, "PermitRootLogin prohibit-password\n") || !strings.Contains(c, "Subsystem\tsftp") {
		t.Errorf("sshd_config a perdu des directives :\n%s", c)
	}
}

// sshd -t refuse : sshd_config n'est PAS touché, les autres groupes le sont.
func TestSSHDRefuseNeBloqueQueSonGroupe(t *testing.T) {
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	for _, rel := range p.tenus() {
		p.ecrire(rel, sansMarqueurs(p.lire(rel)))
	}
	avant := p.lire("etc/ssh/sshd_config")
	f := &fauxSysteme{reponses: sshdRefuse}
	r := Reconcilier(p.env(f))
	if r.Etat != EtatEcart || !strings.Contains(r.Motif, "sshd -t refuse") || !strings.Contains(r.Motif, "not allowed within a Match") {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	if p.lire("etc/ssh/sshd_config") != avant {
		t.Error("sshd_config touché malgré le refus")
	}
	if l, _ := filepath.Glob(p.chemin("etc/ssh/*bak*")); len(l) != 0 {
		t.Errorf("sauvegarde faite alors que rien n'est écrit : %v", l)
	}
	if f.a("systemctl") {
		t.Error("sshd rechargé")
	}
	if LireVersion(p.lire("etc/pam.d/sshd")) != VersionPAM || !strings.Contains(r.Motif, "pam.d/sshd v0→v1") {
		t.Errorf("les piles devaient passer : %s", r.Motif)
	}
}

// Une pile Debian personnalisée (sans « @include common-auth ») : les TROIS
// piles restent telles quelles — tout ou rien —, sshd_config passe.
func TestPileDebianPersonnaliseeRetientLesPilesSeulement(t *testing.T) {
	p := nouveauPoste(t, "debian", true)
	p.installer()
	for _, rel := range p.tenus() {
		p.ecrire(rel, sansMarqueurs(p.lire(rel)))
	}
	p.ecrire("etc/pam.d/gdm-password", "#%PAM-1.0\nauth required pam_unix.so\n")
	login := p.lire("etc/pam.d/login")
	r := Reconcilier(p.env(&fauxSysteme{}))
	if r.Etat != EtatEcart || !strings.Contains(r.Motif, "pam.d/gdm-password : « @include common-auth » absent") {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	if p.lire("etc/pam.d/login") != login {
		t.Error("pam.d/login écrit alors que son groupe est refusé")
	}
	if LireVersion(p.lire("etc/ssh/sshd_config")) != VersionSSHD {
		t.Error("sshd_config retenu par une pile qui n'a rien à voir")
	}
}

// Après une rétrogradation : un fichier marqué plus haut que l'agent n'est
// pas descendu.
func TestUnFichierEnAvanceNEstPasTouche(t *testing.T) {
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	futur := strings.Replace(p.lire("etc/pam.d/login"), "vaultaire-conf v1 ", "vaultaire-conf v7 ", 1) + "# ajout v7\n"
	p.ecrire("etc/pam.d/login", futur)
	r := Reconcilier(p.env(&fauxSysteme{}))
	if r.Etat != EtatConforme || !strings.Contains(r.Motif, "pam.d/login v7 (en avance)") {
		t.Fatalf("%s : %s", r.Etat, r.Motif)
	}
	if p.lire("etc/pam.d/login") != futur {
		t.Error("fichier en avance réécrit")
	}
}

// Les modes et propriétaires d'origine sont gardés.
func TestModeGarde(t *testing.T) {
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	p.ecrire("etc/ssh/sshd_config", sansMarqueurs(p.lire("etc/ssh/sshd_config")))
	_ = os.Chmod(p.chemin("etc/ssh/sshd_config"), 0o600)
	Reconcilier(p.env(&fauxSysteme{}))
	if info, _ := os.Stat(p.chemin("etc/ssh/sshd_config")); info.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}

func TestFichierRequisAbsent(t *testing.T) {
	p := nouveauPoste(t, "rocky", false)
	p.installer()
	_ = os.Remove(p.chemin("etc/nsswitch.conf"))
	r := Reconcilier(p.env(&fauxSysteme{}))
	if r.Etat != EtatEcart || !strings.Contains(r.Motif, "nsswitch.conf : fichier absent") {
		t.Errorf("%s : %s", r.Etat, r.Motif)
	}
}

func TestFamilleInconnue(t *testing.T) {
	if r := Reconcilier(Env{Famille: "arch"}); r.Etat != EtatNonPrisEnCharge {
		t.Errorf("%+v", r)
	}
}

func TestRemettre(t *testing.T) {
	d := t.TempDir()
	f, bak, cree := filepath.Join(d, "f"), filepath.Join(d, "f.bak"), filepath.Join(d, "neuf")
	_ = os.WriteFile(f, []byte("nouveau"), 0o640)
	_ = os.WriteFile(bak, []byte("ancien"), 0o640)
	_ = os.WriteFile(cree, []byte("x"), 0o644)
	if e := remettre([]candidat{{regle: Regle{Nom: "f"}, chemin: f, bak: bak}, {regle: Regle{Nom: "n"}, chemin: cree}}); len(e) != 0 {
		t.Fatal(e)
	}
	if b, _ := os.ReadFile(f); string(b) != "ancien" {
		t.Errorf("%q", b)
	}
	if _, err := os.Stat(cree); err == nil {
		t.Error("fichier créé non retiré")
	}
}

// Rejouer le script, ou produire à partir d'un fichier déjà marqué, ne double
// ni le marqueur ni les lignes de Vaultaire : c'est ce qui fait qu'une montée
// de version remplace le bloc au lieu de l'empiler.
func TestRejouerNeDoubleRien(t *testing.T) {
	for _, famille := range []string{"rocky", "debian"} {
		t.Run(famille, func(t *testing.T) {
			p := nouveauPoste(t, famille, true)
			p.installer()
			premier := map[string]string{}
			for _, rel := range p.tenus() {
				premier[rel] = p.lire(rel)
			}
			p2 := nouveauPoste(t, famille, true)
			p2.racine = p.racine // même poste, script rejoué
			for _, f := range []string{"opt/vaultaire/vaultaire_client/vaultaire_client", "opt/vaultaire/client_conf.json"} {
				p2.ecrire(f, "x")
			}
			for _, m := range []string{"pam_login_custom_module.so", "pam_logout_custom_module.so",
				"pam_ssh_auth_module.so", "libnss_vaultaire.so.2"} {
				p2.ecrire("opt/vaultaire/vaultaire_client/"+famille+"/"+m, famille)
			}
			p2.ecrire("opt/vaultaire/client_conf.json", `{"servers":[{"ip":"10.0.0.1","port":6666}]}`)
			p2.installer()
			regles, _ := Regles(famille, true)
			for _, r := range regles {
				if got := p.lire(r.Rel); got != premier[r.Rel] {
					t.Errorf("%s : le script rejoué change le fichier :\n%s", r.Nom, got)
				}
				if got, _ := r.Produire(premier[r.Rel]); got != premier[r.Rel] {
					t.Errorf("%s : l'agent, sur un fichier déjà à jour, produit autre chose :\n%s", r.Nom, got)
				}
				if n := strings.Count(premier[r.Rel], PrefixeMarqueur+" v"); n != 1 {
					t.Errorf("%s : %d marqueur(s) de version", r.Nom, n)
				}
			}
		})
	}
}
