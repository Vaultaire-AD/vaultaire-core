module vaultaire_client

go 1.26.1

toolchain go1.26.5

require duckynetworkclient/V1 v0.0.0

require gopkg.in/yaml.v3 v3.0.1

require golang.org/x/sys v0.47.0 // indirect

replace duckynetworkclient/V1 => ../ducky-network-sdk-service
