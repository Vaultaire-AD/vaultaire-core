package newclient

import (
	"DUCKY/serveur/database"
	keymanagement "DUCKY/serveur/ducky-network/key_management"
	"DUCKY/serveur/logs"
	"DUCKY/serveur/storage"
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	yaml "gopkg.in/yaml.v3"
)

// generateRandomID génère un ID aléatoire de la longueur spécifiée, suivi de la date actuelle.
// Il utilise un ensemble de caractères alphanumériques pour la génération.
// Si une erreur survient lors de la génération de l'ID, elle est enregistrée dans les logs et renvoyée.
// Le format de l'ID est : <alphanumérique>-<date au format JJ-MM-AAAA>.
// La fonction retourne l'ID généré ou une erreur en cas de problème.
// Cette fonction est utilisée pour générer un ID unique pour le client software.
// Elle est appelée lors de la création d'un nouveau client software pour garantir que chaque client a un identifiant unique.
// Elle utilise un ensemble de caractères alphanumériques pour générer l'ID, ce qui le rend difficile à deviner.
// Le suffixe de l'ID est la date actuelle au format JJ-MM-AAAA, ce qui permet de savoir quand le client a été créé.
// Si une erreur survient lors de la génération de l'ID, elle est enregistrée dans les logs et renvoyée.
// Le résultat est un ID unique qui peut être utilisé pour identifier le client software dans la base de données et dans les fichiers de configuration.
// Il est important de noter que cette fonction utilise le package crypto/rand pour garantir que l'ID est généré de manière sécurisée et aléatoire.
// Elle est conçue pour être utilisée dans le contexte de la création de nouveaux clients software dans l'application Vaultaire AD.
// Elle est appelée par la fonction GenerateClientSoftware pour générer un ID unique pour chaque client software créé.
// Elle est essentielle pour assurer l'unicité des clients software dans le système, ce qui est crucial pour la gestion des configurations et des permissions.
func generateRandomID(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			logs.Write_Log("ERROR", "generateRandomID for client software error : "+err.Error())
			return "", fmt.Errorf("generateRandomID for client software error : %v", err)
		}
		result[i] = charset[index.Int64()]
	}
	currentDate := time.Now().Format("02-01-2006")
	return string(result) + "-" + currentDate, nil
}

func GenerateClientSoftware(logicielType string, isServeur bool) (string, error) {
	// Génération d'un ID unique pour le Computeur
	computeurID, _ := generateRandomID(12)
	// Génération de la paire de clés SSH
	privateKey, publicKey, err := keymanagement.GenerateKeyRSA(4096)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the key pair generation"+err.Error())
		return "", fmt.Errorf("error during the key pair generation : %v", err)
	}
	err = database.Create_ClientSoftware(database.GetDatabase(), computeurID, logicielType, keymanagement.Convert_Public_Key_To_String(publicKey), isServeur)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the creation of the client software in the database"+err.Error())
		return "", fmt.Errorf("error during the creation of the client software in the database : %v", err)
	}

	// Préparation des données pour le fichier YAML
	clientSoftware := storage.NewClientSoftware{}
	clientSoftware.NewClient.Computeur_id = computeurID
	clientSoftware.NewClient.Logiciel_type = logicielType
	clientSoftware.NewClient.IsServeur = isServeur

	// Définir le chemin du dossier et le créer
	path := storage.Client_Conf_path + "/clientsoftware"
	dirPath := filepath.Join(path, computeurID)
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		logs.Write_Log("ERROR", "Error during the folder creation : "+err.Error())
		return "", fmt.Errorf("error during the folder creation : %v", err)
	}

	// Écriture du fichier YAML
	yamlPath := filepath.Join(dirPath, "client_software.yaml")
	yamlFile, err := os.Create(yamlPath)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the creation of the YAML file : "+err.Error())
		return "", fmt.Errorf("error during the creation of the YAML file : %v", err)
	}
	defer func() {
		if err := yamlFile.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("ERROR", "Error closing connection: "+err.Error())
		}
	}()

	encoder := yaml.NewEncoder(yamlFile)
	encoder.SetIndent(2)
	if err := encoder.Encode(&clientSoftware); err != nil {
		logs.Write_Log("ERROR", "Error during the YAML encoding : "+err.Error())
		return "", fmt.Errorf("error during the YAML encoding : %v", err)
	}

	// Écriture de la clé privée
	privateKeyPath := filepath.Join(dirPath, "private_key.pem")
	err = keymanagement.SavePEMKey(privateKeyPath, privateKey)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the private key saving : "+err.Error())
	}
	// Écriture de la clé publique
	publicKeyPath := filepath.Join(dirPath, "public_key.pem")
	err = keymanagement.SavePEMKeyPublic(publicKeyPath, publicKey)
	if err != nil {
		logs.Write_Log("ERROR", "Error during the public key saving : "+err.Error())
	}

	fmt.Printf("Client software configuration et clés générées avec succès dans : %s\n", dirPath)
	return computeurID, nil
}
