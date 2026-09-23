// Package version porte l'identité de version de l'agent Windows.
//
// Même partage que l'agent Linux et le proxy : la forme et le type viennent du
// SDK, ce paquet ne déclare que ce qui est propre à ce binaire.
package version

import sdkversion "duckynetworkclient/V1/duckynetwork/version"

// Version de l'agent Windows.
//
// Une release la remplace à la compilation (-ldflags -X) : une constante ne
// pourrait pas l'être. La valeur écrite ici ne sert qu'aux builds locaux ;
// majeure et mineure doivent suivre le fichier VERSION à la racine.
var Version = "2.2.0"

// Commit et Date sont posés à la compilation par build.sh.
var (
	Commit = "dev"
	Date   = "inconnue"
)

// Info rend la version de CET agent.
func Info() sdkversion.Info {
	return sdkversion.Info{
		Composant:  "vaultaire_client_windows",
		Semantique: Version,
		Commit:     Commit,
		Date:       Date,
	}
}

// SDK rend la version du socle réseau lié à ce binaire.
func SDK() sdkversion.Info { return sdkversion.SDK() }
