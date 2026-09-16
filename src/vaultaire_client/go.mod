module vaultaire_client

go 1.26.1
toolchain go1.26.5

require duckynetworkclient/V1 v0.0.0

require gopkg.in/yaml.v2 v2.4.0

replace duckynetworkclient/V1 => ../ducky-network-sdk-service
