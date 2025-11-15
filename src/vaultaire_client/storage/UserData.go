package storage

var Username string
var AES_key []byte

var Authentification_PAM = make(chan string)
var Authentification_SSHpubkey = make(chan string, 1)

var IsAdmin = false
