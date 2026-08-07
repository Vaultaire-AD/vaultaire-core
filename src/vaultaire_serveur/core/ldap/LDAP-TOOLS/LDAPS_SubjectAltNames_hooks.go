package ldaptools

import (
	"net"
	"os"
)

// Points d'injection pour les tests.
//
// La détection interroge la machine : son nom, ses interfaces. Un test qui les
// laisserait tels quels vérifierait la machine de compilation et non le code —
// il passerait ici et échouerait sur une autre, ou l'inverse, ce qui est pire.
var (
	osHostname        = os.Hostname
	netLookupCNAME    = net.LookupCNAME
	netInterfaceAddrs = net.InterfaceAddrs
)
