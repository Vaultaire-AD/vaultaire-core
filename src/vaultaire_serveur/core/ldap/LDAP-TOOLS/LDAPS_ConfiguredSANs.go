package ldaptools

import "vaultaire/core/storage"

// ConfiguredDNSNames et ConfiguredIPs lisent les SAN déclarés en configuration.
//
// Isolées dans leur propre fichier pour que la construction du jeu de SAN
// (BuildSANSet) reste testable sans dépendre de l'état global de la
// configuration : les tests appellent BuildSANSet directement.
func ConfiguredDNSNames() []string { return storage.Ldaps_TLS_DNSNames }

func ConfiguredIPs() []string { return storage.Ldaps_TLS_IPs }
