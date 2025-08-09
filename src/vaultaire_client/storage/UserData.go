package storage

var Username string
var AES_key []byte

var Authentification_PAM = make(chan string)
var IsAdmin = false
