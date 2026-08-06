package module

import "duckynetworkclient/V1/duckynetwork/serveurauth"

// HaveServeurKey délègue à serveurauth, qui possède le fichier.
//
// Conservée pour ne pas casser les appelants existants ; le chemin n'est plus
// écrit qu'à un seul endroit.
func HaveServeurKey() bool { return serveurauth.HaveServeurKey() }
