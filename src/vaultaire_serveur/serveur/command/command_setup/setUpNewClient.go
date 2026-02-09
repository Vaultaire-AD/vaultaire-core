package commandsetup

import (
	duckykey "vaultaire/serveur/ducky-network/key_management"
	"vaultaire/serveur/logs"
	"vaultaire/serveur/storage"
	"os"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// setup un nouveau client en se connectant dessus
func DeployFilesAndRunCommands(computerID, username, password, serverIP string) string {
	// Récupérer les clés depuis la BDD et créer les fichiers temporaires
	_, _, err := duckykey.EnsureClientSoftwareKeyFiles(computerID)
	if err != nil {
		return "Erreur : Impossible de récupérer les clés depuis la BDD pour " + computerID + " : " + err.Error()
	}

	// Liste des fichiers à envoyer (les clés sont maintenant créées depuis la BDD)
	path := storage.Client_Conf_path + "/clientsoftware/" + computerID + "/"
	files := []string{path + "client_software.yaml", path + "private_key.pem", path + "public_key.pem"}
	// Vérification de l'existence des fichiers locaux
	for _, file := range files {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return ("Erreur : Le fichier %s n'existe pas" + file)
		}
	}

	// Configuration du client SSH
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Connexion au serveur SSH
	client, err := ssh.Dial("tcp", serverIP+":22", config)
	if err != nil {
		return ("Erreur de connexion SSH: %v" + err.Error())
	}
	defer func() {
		if err := client.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("DEBUG", "command_setup: close failed: "+err.Error())
		}
	}()

	// Création du client SFTP
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		return ("Erreur de connexion SFTP: %v" + err.Error())
	}

	defer func() {
		if err := sftpClient.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("DEBUG", "command_setup: close failed: "+err.Error())
		}
	}()

	// Transférer chaque fichier vers /opt/
	for _, file := range files {
		uploadPath := file

		// Ouvrir le fichier local
		srcFile, err := os.Open(file)
		if err != nil {
			return ("Erreur d'ouverture du fichier " + file + ": %v" + err.Error())
		}

		defer func() {
			if err := srcFile.Close(); err != nil {
				// Handle or log the error
				logs.Write_Log("DEBUG", "command_setup: close failed: "+err.Error())
			}
		}()

		// Créer le fichier distant
		dstFile, err := sftpClient.Create(uploadPath)
		if err != nil {
			return ("Erreur de création du fichier distant " + uploadPath + " : " + err.Error())
		}
		defer func() {
			if err := dstFile.Close(); err != nil {
				// Handle or log the error
				logs.Write_Log("DEBUG", "command_setup: close failed: "+err.Error())
			}
		}()

		// Copier le contenu du fichier local vers le serveur
		_, err = dstFile.ReadFrom(srcFile)
		if err != nil {
			return ("Erreur lors du transfert du fichier " + file + " : " + err.Error())
		}

		//fmt.Printf("Fichier %s transféré avec succès vers %s\n", file, uploadPath)
	}

	// Exécuter les commandes via SSH
	commands := []string{
		"mv /opt/pam*.c /usr/lib64/security/",
		"mkdir /opt/vaultaire",
		"mv /opt/vaultaire_serveur /opt/vaultaire/",
		"mkdir /opt/vaultaire/.ssh",
		"mv /opt/*.pem /opt/vaultaire/.ssh/",
		"mv /opt/client_software.yaml /opt/vaultaire/.ssh/",
		"chmod 700 -R /opt/vaultaire",
	}

	// Démarrer une session SSH
	session, err := client.NewSession()
	if err != nil {
		return ("Erreur lors de l'ouverture de la session SSH: " + err.Error())
	}
	defer func() {
		if err := client.Close(); err != nil {
			// Handle or log the error
			logs.Write_Log("DEBUG", "command_setup: close failed: "+err.Error())
		}
	}()

	// Exécuter les commandes une par une
	for _, cmd := range commands {
		//fmt.Println("Exécution de la commande:", cmd)
		_, err := session.CombinedOutput(cmd)
		if err != nil {
			return ("Erreur lors de l'exécution de la commande " + cmd + ": " + err.Error())
		}
	}
	return "Déploiement terminé avec succès !"
}

// func main() {
// 	// Exemple d'appel à la fonction
// 	DeployFilesAndRunCommands("12345", "user", "password", "192.168.1.100")
// }
