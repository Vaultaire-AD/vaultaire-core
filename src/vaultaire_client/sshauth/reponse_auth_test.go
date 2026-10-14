package sshauth

import (
	"strings"
	"testing"

	"duckynetworkclient/V1/duckynetwork/storage"
	"vaultaire_client/pamstate"
	"vaultaire_client/tools/sshreq"
)

// TO-DO 188 : les clés de 03_02 arrivent jusqu'au canal PAM.
//
// Elles s'arrêtaient à l'agent. Le gestionnaire PAM rendait au module une
// liste vide, et le module la réécrivait dans authorized_keys juste après que
// l'agent y avait posé les bonnes : le fichier finissait VIDE.
func TestLesClesDe0302ArriventAuCanalPAM(t *testing.T) {
	ancienP, ancienG := provisionner, appliquerGroupes
	t.Cleanup(func() { provisionner, appliquerGroupes = ancienP, ancienG })

	var clesProvisionnees string
	provisionner = func(u string, admin bool, cles string) error {
		clesProvisionnees = cles
		return nil
	}
	appliquerGroupes = func(u string, g []string) ([]string, error) { return g, nil }

	canal := make(chan pamstate.AuthResult, 1)
	sshreq.Register("alice@dom", canal)
	t.Cleanup(func() { sshreq.Remove("alice@dom") })

	SSH_Auth_Manager(storage.Trames_struct_client{
		Message_Order: []string{"03", "02"},
		Content: strings.Join([]string{
			"alice@dom", "true", "groups:devs", "notice:bonjour",
			"ssh-ed25519 AAAAa poste", "ssh-rsa BBBBb portable",
		}, "\n"),
	}, nil)

	var r pamstate.AuthResult
	select {
	case r = <-canal:
	default:
		t.Fatal("aucune réponse sur le canal PAM")
	}
	if !r.Accepte || r.Type != "AUTH" || !r.IsAdmin {
		t.Errorf("verdict = %+v", r)
	}
	attendu := "ssh-ed25519 AAAAa poste\nssh-rsa BBBBb portable"
	if r.SSHKeys != attendu {
		t.Errorf("clés au canal PAM = %q, attendu %q", r.SSHKeys, attendu)
	}
	if clesProvisionnees != attendu {
		t.Errorf("clés provisionnées = %q, attendu %q", clesProvisionnees, attendu)
	}
	if strings.Contains(r.SSHKeys, "groups:") || strings.Contains(r.SSHKeys, "notice:") {
		t.Errorf("une ligne de contrôle est partie avec les clés : %q", r.SSHKeys)
	}
}

// TO-DO 171 : le motif de 03_03 arrive jusqu'au canal PAM, tel que le core
// l'a écrit — le filtre est dans le gestionnaire PAM.
func TestLeMotifDe0303ArriveAuCanalPAM(t *testing.T) {
	canal := make(chan pamstate.AuthResult, 1)
	sshreq.Register("bob@dom", canal)
	t.Cleanup(func() { sshreq.Remove("bob@dom") })

	SSH_Auth_Manager(storage.Trames_struct_client{
		Message_Order: []string{"03", "03"},
		Content:       "bob@dom\npassword expired",
	}, nil)

	r, ok := <-canal
	if !ok {
		t.Fatal("canal fermé sans verdict")
	}
	if r.Accepte || r.MotifRefus != "password expired" {
		t.Errorf("verdict = %+v, attendu un refus portant « password expired »", r)
	}
}
