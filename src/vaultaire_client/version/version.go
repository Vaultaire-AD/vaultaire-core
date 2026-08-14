// Package version porte l'identité de version de l'agent.
//
// La forme et le type viennent du SDK — voir
// `duckynetworkclient/V1/duckynetwork/version`. Ce paquet ne déclare que ce qui
// est PROPRE à l'agent : sa version sémantique, et le commit avec lequel il a
// été construit.
//
// # Pourquoi l'agent a sa propre version, distincte de celle du SDK
//
// Les deux ne bougent pas ensemble. Une correction dans le provisionnement des
// groupes ne touche pas au socle réseau ; un durcissement du protocole ne
// change rien à l'agent. Un seul numéro pour les deux obligerait à monter l'un
// pour une raison qui ne le concerne pas — et le rendrait donc faux comme
// promesse de compatibilité.
//
// Le point 39 demande explicitement les deux : « la version de l'agent […]
// ainsi que la version du SDK ducky utilisé pour build l'image ».
package version

import sdkversion "duckynetworkclient/V1/duckynetwork/version"

// Version de l'agent Vaultaire. Constante, décidée par un humain.
const Version = "2.1.0"

// Commit et Date sont posés à la compilation par auto-compil.sh.
//
// Repli « dev » / « inconnue » : un binaire construit à la main se reconnaît
// dans l'inventaire du parc, au lieu de s'y confondre avec les autres.
var (
	Commit = "dev"
	Date   = "inconnue"
)

// Info rend la version de CET agent.
func Info() sdkversion.Info {
	return sdkversion.Info{
		Composant:  "vaultaire_client",
		Semantique: Version,
		Commit:     Commit,
		Date:       Date,
	}
}

// SDK rend la version du socle réseau lié à ce binaire.
//
// Lue depuis le paquet du SDK, donc depuis ce qui est RÉELLEMENT compilé dans
// ce binaire. La recopier ici en ferait une valeur à tenir d'accord, et elle
// finirait par annoncer un socle que l'agent n'embarque pas.
func SDK() sdkversion.Info { return sdkversion.SDK() }
