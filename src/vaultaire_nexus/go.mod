module vaultaire_nexus

go 1.26.1

toolchain go1.26.5

require (
	duckynetworkclient/V1 v0.0.0
	github.com/go-asn1-ber/asn1-ber v1.5.8
	github.com/klauspost/compress v1.20.0
	github.com/ulikunitz/xz v0.5.16
	gopkg.in/yaml.v2 v2.4.0
)

replace duckynetworkclient/V1 => ../ducky-network-sdk-service
