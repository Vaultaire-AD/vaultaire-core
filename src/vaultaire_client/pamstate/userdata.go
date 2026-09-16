package pamstate

// Username est l'identité annoncée dans les trames 01_01 et 06_*.
//
// ⚠️ Elle n'était JAMAIS affectée : l'agent envoyait donc une chaîne vide. Le
// serveur ne s'en sert que pour tracer — SetIdentity en 01_01, rien du tout en
// 06_04 —, si bien que le défaut ne se voyait que dans les journaux du core,
// sous la forme de sessions sans nom.
//
// Elle vaut « vaultaire » par défaut, qui est ce que la session MACHINE est
// réellement. Le socle envoie déjà cette valeur en dur dans 01_01 ; la poser ici
// aligne les trames 06_* sur la même identité, au lieu de laisser les deux se
// contredire.
var Username = "vaultaire"
var AES_key []byte

var Authentification_PAM = make(chan string)

var IsAdmin = false
