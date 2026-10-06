package dbcertificates

import "errors"

// ErrCertificatIntrouvable distingue « ce certificat n'existe pas en base » de
// toutes les autres façons dont une lecture peut échouer.
//
// # Le défaut que ce sentinelle corrige
//
// L'amorçage de la clé SSH de déploiement prenait TOUTE erreur pour « clé
// absente » et régénérait. Sur un second démarrage, l'erreur venait en réalité
// de l'écriture du fichier ; la clé, elle, était bien en base. La régénération
// butait alors sur « certificat server_login_client existe déjà », et le core
// s'arrêtait (TO-DO 94).
//
// Comparer le message d'erreur aurait marché jusqu'à ce que quelqu'un le
// reformule. Un sentinelle se compare avec errors.Is et ne se reformule pas.
var ErrCertificatIntrouvable = errors.New("certificat non trouvé")
