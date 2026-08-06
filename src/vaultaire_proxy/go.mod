module vaultaire_proxy

go 1.25.0

require duckynetworkclient/V1 v0.0.0

require gopkg.in/yaml.v2 v2.4.0 // indirect

replace duckynetworkclient/V1 => ../ducky-network-sdk-service
