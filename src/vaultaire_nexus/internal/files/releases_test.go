package files

import "testing"

func TestParseAssetName(t *testing.T) {
	bons := map[string][3]string{
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz":                     {"vaultaire_client", "2.3.0", "linux-amd64"},
		"vaultaire_server-2.3.0-linux-amd64.tar.gz":                      {"vaultaire_server", "2.3.0", "linux-amd64"},
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.manifest":      {"vaultaire_client", "2.3.0", "linux-amd64"},
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.debian.manifest.sig": {"vaultaire_client", "2.3.0", "linux-amd64"},
	}
	for fn, attendu := range bons {
		n, v, a, ok := ParseAssetName(fn)
		if !ok || [3]string{n, v, a} != attendu {
			t.Errorf("%s : %q %q %q %v", fn, n, v, a, ok)
		}
	}
	for _, fn := range []string{
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.manifest",       // sans famille
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.sig",      // signature sans manifeste
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.Rocky.manifest", // majuscule
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.manifest.sig.sig",
		"vaultaire_client-v2.3.0-linux-amd64.rocky.manifest", // sans l'archive
		"SHA256SUMS",
	} {
		if _, _, _, ok := ParseAssetName(fn); ok {
			t.Errorf("%s : reconnu", fn)
		}
	}
}

// Une release porte l'archive et ses manifestes ; SHA256SUMS les liste tous.
// docker-update.sh n'en souffre pas : il ne vérifie que les lignes des
// archives qu'il installe (TO-DO 202).
func TestLesManifestesSontDansLaRelease(t *testing.T) {
	r := Release{Tag: "v2.3.0", Version: "2.3.0"}
	for _, fn := range []string{
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz",
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.manifest",
		"vaultaire_client-v2.3.0-linux-amd64.tar.gz.rocky.manifest.sig",
	} {
		r.Assets = append(r.Assets, catalogPackage(fn))
	}
	sums := string(r.SHA256SUMS())
	for _, a := range r.Assets {
		if !contient(sums, "  "+a.Filename+"\n") {
			t.Errorf("SHA256SUMS sans %s :\n%s", a.Filename, sums)
		}
	}
}
