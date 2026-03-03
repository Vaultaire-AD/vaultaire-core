package commandcreate

import (
	"vaultaire/serveur/database"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Fonction pour générer un salt aléatoire
func generateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt)
	return salt, err
}

// Fonction principale de création utilisateur
func create_User(command_list []string) string {
	if len(command_list) < 5 {
		return "Erreur : create -u username domain password 06/02/1992"
	}

	username := command_list[1]
	domain := command_list[2]
	password := command_list[3]
	birthdate := command_list[4]
	firstname := username
	lastname := username

	if strings.Contains(username, ".") {
		list := strings.Split(username, ".")
		firstname = list[0]
		lastname = list[1]
	}
	if len(command_list) == 7 {
		firstname = command_list[5]
		lastname = command_list[6]
	}

	if strings.ToLower(username) == "vaultaire" {
		return "Erreur : vous ne pouvez pas créer un utilisateur avec ce nom, compte réservé par le service"
	}

	// Générer un salt
	salt, err := generateSalt(16)
	if err != nil {
		return "Erreur lors de la génération du salt"
	}
	saltHex := hex.EncodeToString(salt)

	// Appliquer le hash SHA256 sur le mot de passe + salt
	saltedPassword := append(salt, []byte(password)...)
	hash := sha256.Sum256(saltedPassword)
	hashHex := hex.EncodeToString(hash[:])

	// Enregistrer dans la base de données
	err = database.Create_New_User(
		database.GetDatabase(),
		username,
		firstname,
		lastname,
		username+"@"+domain,
		hashHex, // mot de passe hashé
		saltHex, // salt (en hex)
		birthdate,
		time.Now().Format("2006-01-02 15:04:05"),
	)
	if err != nil {
		return "Erreur lors de la création de l'utilisateur : " + err.Error()
	}

	return "Utilisateur créé avec succès"
}
