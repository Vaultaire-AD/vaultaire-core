package autoaddclientgo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TO-DO 71 : `create -c … -join` sur Debian et Ubuntu.

const osReleaseDebian = `PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
`

const osReleaseUbuntu = `PRETTY_NAME="Ubuntu 24.04.5 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
ID=ubuntu
ID_LIKE=debian
`

const osReleaseRocky = `NAME="Rocky Linux"
VERSION="9.4 (Blue Onyx)"
ID="rocky"
ID_LIKE="rhel centos fedora"
PLATFORM_ID="platform:el9"
`

func TestLeScriptSuitLaDistribution(t *testing.T) {
	for _, cas := range []struct{ nom, osRelease, script string }{
		{"debian", osReleaseDebian, "debian.sh"},
		{"ubuntu", osReleaseUbuntu, "debian.sh"},
		{"rocky", osReleaseRocky, "rocky.sh"},
		{"rocky sans guillemets", "ID=rocky\n", "rocky.sh"},
		{"fins de ligne Windows", "NAME=x\r\nID=ubuntu\r\n", "debian.sh"},
	} {
		script, distribution, err := ScriptDInstallation(cas.osRelease)
		if err != nil || script != cas.script {
			t.Errorf("%s : script %q, erreur %v — attendu %q", cas.nom, script, err, cas.script)
		}
		if distribution == "" {
			t.Errorf("%s : distribution non rendue", cas.nom)
		}
	}
}

// Une distribution qui « ressemble » à une autre n'en reçoit pas le script :
// il réécrit PAM, NSS et SSH.
func TestUneDistributionVoisineEstRefusee(t *testing.T) {
	for nom, osRelease := range map[string]string{
		"alma (ID_LIKE rhel)":      "ID=\"almalinux\"\nID_LIKE=\"rhel centos fedora\"\n",
		"mint (ID_LIKE ubuntu)":    "ID=linuxmint\nID_LIKE=\"ubuntu debian\"\n",
		"variante nommée debian":   "ID=autre\nVARIANT_ID=debian\n",
		"debian en commentaire":    "# ID=debian\nID=suse\n",
		"fichier vide":             "",
		"sans ligne ID":            "NAME=Quelquechose\nVERSION_ID=debian\n",
		"ID=debian dans une autre": "BUILD_ID=debian\nID=arch\n",
	} {
		script, _, err := ScriptDInstallation(osRelease)
		if err == nil {
			t.Errorf("%s : script %q choisi, attendu un refus", nom, script)
		}
	}
	// Le refus nomme ce qui a été lu, et ce qui est pris en charge.
	_, _, err := ScriptDInstallation("ID=almalinux\n")
	if err == nil || !strings.Contains(err.Error(), "almalinux") || !strings.Contains(err.Error(), "debian, ubuntu, rocky") {
		t.Errorf("message de refus : %v", err)
	}
}

// Chaque script que le choix peut rendre EXISTE dans le dépôt. C'est le défaut
// du TO-DO 71 : « debian.sh » et « ubuntu.sh » étaient demandés, et n'étaient
// écrits nulle part.
func TestChaqueScriptChoisiExiste(t *testing.T) {
	dossier := "../../../../../automatisation/auto_deployements"
	if _, err := os.Stat(dossier); err != nil {
		t.Fatalf("%s introuvable (%v) : le dossier a-t-il été déplacé ?", dossier, err)
	}
	for _, osRelease := range []string{osReleaseDebian, osReleaseUbuntu, osReleaseRocky} {
		script, _, err := ScriptDInstallation(osRelease)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dossier, script))
		if err != nil {
			t.Errorf("le script %s est choisi mais n'existe pas : %v", script, err)
			continue
		}
		if info.Size() < 1000 {
			t.Errorf("le script %s est presque vide (%d octets)", script, info.Size())
		}
	}
}
