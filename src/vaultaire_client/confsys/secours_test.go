package confsys

import (
	"strings"
	"testing"
)

// Tous les gabarits et toutes les piles branchées passent la porte de secours.
func TestLesGabaritsGardentLaPorteDeSecours(t *testing.T) {
	for nom, pile := range map[string]string{"login rocky": pileLoginRocky, "sshd rocky": pileSSHDRocky,
		"gdm rocky": pileGDMRocky} {
		if err := VerifierPorteDeSecours(pile); err != nil {
			t.Errorf("%s : %v", nom, err)
		}
	}
	for nom, b := range map[string][3]string{
		"login debian": {origLoginDebian, authLoginDebian, sessionDebian},
		"sshd debian":  {origSSHDDebian, authSSHDDebian, ""},
		"gdm debian":   {origGDMDebian, authGDMDebian, sessionDebian},
	} {
		pile, err := brancherPileDebian(b[0], b[1], b[2])
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifierPorteDeSecours(pile); err != nil {
			t.Errorf("%s : %v", nom, err)
		}
	}
}

// Et ce qui fermerait la machine aux comptes locaux est refusé.
func TestLaPorteDeSecoursRefuse(t *testing.T) {
	for _, k := range []struct{ nom, pile, contient string }{
		{"module absent", "#%PAM-1.0\nauth substack system-auth\n", "aucune ligne"},
		{"default=die sans ignore", "auth [success=done default=die] pam_ssh_auth_module.so\nauth substack password-auth\n", "ignore=ignore"},
		{"required", "auth required pam_login_custom_module.so\nauth substack system-auth\n", "ignore=ignore"},
		{"rien derrière", "auth [success=done ignore=ignore default=die] pam_ssh_auth_module.so\naccount include password-auth\n", "pas d'authentification locale"},
		{"un requisite avant la pile locale", "auth [success=done ignore=ignore default=die] pam_ssh_auth_module.so\n" +
			"auth requisite pam_deny.so\nauth substack password-auth\n", "coupe le chemin"},
		{"un die avant la pile locale", "auth [success=done ignore=ignore default=die] pam_login_custom_module.so\n" +
			"auth [success=ok default=die] pam_faillock.so\n@include common-auth\n", "coupe le chemin"},
		{"pile locale en commentaire", "auth [success=done ignore=ignore default=die] pam_ssh_auth_module.so\n# @include common-auth\n", "pas d'authentification locale"},
	} {
		if err := VerifierPorteDeSecours(k.pile); err == nil || !strings.Contains(err.Error(), k.contient) {
			t.Errorf("%s : %v", k.nom, err)
		}
	}
}

// Les versions : un marqueur par gabarit, à la version de sa règle.
func TestMarqueurs(t *testing.T) {
	if LireVersion("#%PAM-1.0\nauth x\n") != 0 || LireVersion(MarquePAM+"\n") != VersionPAM ||
		LireVersion("x\n# vaultaire-conf v12 - y\n") != 12 || LireVersion("# vaultaire-conf - fin du bloc Vaultaire\n") != 0 {
		t.Error("LireVersion")
	}
	for nom, g := range map[string]string{"bloc sshd": blocSSHD, "dconf": dconfGDM} {
		if LireVersion(g) != 1 {
			t.Errorf("%s : v%d", nom, LireVersion(g))
		}
	}
}
