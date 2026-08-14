// Package version porte l'identité de version du proxy.
//
// Même partage que pour l'agent : la forme et le type viennent du SDK, ce
// paquet ne déclare que ce qui est propre au proxy.
package version

import sdkversion "duckynetworkclient/V1/duckynetwork/version"

// Version du proxy Vaultaire. Constante, décidée par un humain.
const Version = "2.1.0"

// Commit et Date sont posés à la compilation par auto-compil.sh.
var (
	Commit = "dev"
	Date   = "inconnue"
)

// Info rend la version de CE proxy.
func Info() sdkversion.Info {
	return sdkversion.Info{
		Composant:  "vaultaire_proxy",
		Semantique: Version,
		Commit:     Commit,
		Date:       Date,
	}
}

// SDK rend la version du socle réseau lié à ce binaire.
func SDK() sdkversion.Info { return sdkversion.SDK() }
