package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
)

func AddSSHKeyToClient(user, host string) error {
	pubKeyPath := os.Getenv("VAULTAIRE_pubKeyLogin")
	if pubKeyPath == "" {
		return fmt.Errorf("❌ Variable d’environnement VAULTAIRE_pubKeyLogin non définie")
	}
	fmt.Printf("📁 Clé publique : %s\n", pubKeyPath)
	fmt.Printf("📡 Tentative d’envoi de la clé publique à %s@%s\n", user, host)
	cmd := exec.Command("ssh-copy-id", "-f", "-i", pubKeyPath, fmt.Sprintf("%s@%s", user, host))

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("❌ Échec de ssh-copy-id : %v\n%s", err, stderr.String())
	}

	fmt.Println("✅ Clé publique ajoutée avec succès.")
	return nil
}

func readFullResponse(conn net.Conn) (string, error) {
	var result strings.Builder
	buf := make([]byte, 1024)

	for {
		n, err := conn.Read(buf)
		if n > 0 {
			result.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF {
				// Fin normale de la lecture
				break
			}
			return "", err
		}
	}
	return result.String(), nil
}

func main() {
	// Vérifier si des arguments ont été passés
	if len(os.Args) > 1 {
		// Joindre les arguments en une seule chaîne de caractères
		command := strings.Join(os.Args[1:], " ")
		if strings.Contains(command, "-join") {
			parts := strings.Fields(command)
			for i := 0; i < len(parts)-2; i++ {
				if parts[i] == "-join" {
					ip := parts[i+1]
					username := parts[i+2]

					fmt.Println("🔑 Détection de -join avec IP:", ip, "et utilisateur:", username)
					if err := AddSSHKeyToClient(username, ip); err != nil {
						fmt.Println(err)
					} else {
						fmt.Println("🔑 Clé SSH ajoutée avec succès.")
					}
					break
				}
			}
		}
		// Se connecter au serveur principal via le socket UNIX
		conn, err := net.Dial("unix", "/opt/vaultaire/vaultaire.sock")
		if err != nil {
			fmt.Println("Erreur connexion serveur:", err)
			return
		}
		defer conn.Close()

		// Envoyer la commande au serveur
		_, err = conn.Write([]byte(command))
		if err != nil {
			fmt.Println("Erreur envoi commande:", err)
			return
		}

		// Lire la réponse du serveur
		// buf := make([]byte, 1024)
		// n, err := conn.Read(buf)
		// if err != nil {
		// 	fmt.Println("Erreur lecture réponse:", err)
		// 	return
		// }

		// // Afficher la réponse
		// fmt.Println(strings.TrimSpace(string(buf[:n])))
		response, err := readFullResponse(conn)
		if err != nil {
			fmt.Println("Erreur lecture réponse:", err)
			return
		}
		fmt.Println(strings.TrimSpace(response))
	} else {
		// Si aucun argument n'est fourni, démarrer le mode interactif
		reader := bufio.NewReader(os.Stdin)

		for {
			fmt.Print("vaultaire> ")
			input, _ := reader.ReadString('\n')
			command := strings.TrimSpace(input)

			if command == "exit" {
				fmt.Println("Fermeture de Vaultaire CLI...")
				break
			}
			if strings.Contains(command, "-join") {
				parts := strings.Fields(command)
				for i := 0; i < len(parts)-2; i++ {
					if parts[i] == "-join" {
						ip := parts[i+1]
						username := parts[i+2]

						fmt.Println("🔑 Détection de -join avec IP:", ip, "et utilisateur:", username)
						if err := AddSSHKeyToClient(username, ip); err != nil {
							fmt.Println(err)
						}
						fmt.Println("🔑 Clé SSH ajoutée avec succès.")
						break
					}
				}
			}

			// Se connecter au serveur principal via le socket UNIX
			conn, err := net.Dial("unix", "/opt/vaultaire/vaultaire.sock")
			if err != nil {
				fmt.Println("Erreur connexion serveur:", err)
				continue
			}
			defer conn.Close()

			// Envoyer la commande au serveur
			_, err = conn.Write([]byte(command))
			if err != nil {
				fmt.Println("Erreur envoi commande:", err)
				continue
			}

			// Lire la réponse du serveur
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				fmt.Println("Erreur lecture réponse:", err)
				continue
			}

			// Afficher la réponse
			fmt.Println(strings.TrimSpace(string(buf[:n])))
		}
	}
}
