package serveur

// Prove_Identity is a function that processes the identity proof request from the client.
// It takes a string containing the lines of the request and a session key integrity string.
// It returns a string that contains the server's response, which includes the session key integrity and the original message.
func Prove_Identity(lines string, sessionkeyintegrity string) string {
	messagebyte := []byte(lines)
	//the server just do his proof of work during the decrypt of the message before the trame manager
	// and now he just retrun the value and encrypt with the client software public key
	return ("01_02\nserver_central\n" + sessionkeyintegrity + "\n" + string(messagebyte))
}
