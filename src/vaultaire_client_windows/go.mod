module vaultaire_client_windows

go 1.26.1

toolchain go1.26.5

require (
	duckynetworkclient/V1 v0.0.0
	golang.org/x/sys v0.47.0
	vaultaire_client v0.0.0-00010101000000-000000000000
)

require gopkg.in/yaml.v3 v3.0.1 // indirect

replace duckynetworkclient/V1 => ../ducky-network-sdk-service

replace vaultaire_client => ../vaultaire_client
