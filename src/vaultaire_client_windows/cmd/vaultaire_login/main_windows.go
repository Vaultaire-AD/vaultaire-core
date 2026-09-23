//go:build windows

// vaultaire_login — éprouver la chaîne d'authentification sans écran de
// connexion.
//
// Cet outil fait EXACTEMENT ce que fera le Credential Provider : il ouvre le
// tube nommé de l'agent, pose une requête, lit le verdict. Rien de plus.
//
// Il existe pour une raison précise : déverminer un Credential Provider se fait
// dans LogonUI.exe, un processus qu'on ne peut ni attacher facilement ni voir
// planter sans perdre l'écran de connexion de la machine. Tout ce qui peut être
// éprouvé AVANT — le tube et ses droits, le format des messages, le tunnel vers
// le core, le provisionnement du compte local — doit l'être ici.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows"

	"vaultaire_client_windows/ipc"
)

func main() {
	utilisateur := flag.String("u", "", "utilisateur du domaine (alice@test.fr)")
	etat := flag.Bool("etat", false, "demander seulement si l'agent est raccordé à un core")
	verifier := flag.Bool("check", false, "vérifier le mot de passe SANS provisionner de compte local")
	delai := flag.Duration("delai", 30*time.Second, "délai d'attente total")
	flag.Parse()

	if *etat {
		repondre(ipc.Requete{Type: ipc.TypeEtat}, *delai)
		return
	}
	if *utilisateur == "" {
		fmt.Fprintln(os.Stderr, "usage : vaultaire_login -u alice@test.fr [-check] [-etat]")
		os.Exit(2)
	}

	motDePasse, err := lireMotDePasse()
	if err != nil {
		fmt.Fprintln(os.Stderr, "lecture du mot de passe :", err)
		os.Exit(1)
	}

	typ := ipc.TypeAuth
	if *verifier {
		typ = ipc.TypeCheck
	}
	repondre(ipc.Requete{Type: typ, Utilisateur: *utilisateur, MotDePasse: motDePasse}, *delai)
}

func repondre(req ipc.Requete, delai time.Duration) {
	rep, err := ipc.Demander(req, delai)
	// Le mot de passe ne survit pas à l'appel.
	req.MotDePasse = ""
	if err != nil {
		fmt.Fprintln(os.Stderr, "vaultaire :", err)
		fmt.Fprintln(os.Stderr, "  le service VaultaireAgent tourne-t-il ? (sc query VaultaireAgent)")
		os.Exit(1)
	}

	fmt.Println("statut         :", rep.Statut)
	if rep.Message != "" {
		fmt.Println("message        :", rep.Message)
	}
	if req.Type == ipc.TypeEtat {
		fmt.Println("raccordé       :", rep.Raccorde)
	}
	if rep.CompteLocal != "" {
		fmt.Println("compte local   :", rep.CompteLocal)
		fmt.Println("administrateur :", rep.Administrateur)
	}
	if rep.Statut != ipc.StatutSucces {
		os.Exit(1)
	}
}

// lireMotDePasse lit sans écho quand c'est une console, et accepte une entrée
// redirigée sinon — un script de recette n'a pas de console.
//
// L'écho est coupé en retirant ENABLE_ECHO_INPUT du mode de la console, puis
// remis quoi qu'il arrive : une console laissée sans écho après une erreur
// donne un terminal muet, et l'utilisateur croit sa machine bloquée.
func lireMotDePasse() (string, error) {
	entree, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return "", err
	}
	var mode uint32
	if err := windows.GetConsoleMode(entree, &mode); err != nil {
		// Entrée redirigée : pas de console, donc pas d'écho à couper.
		ligne, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimRight(ligne, "\r\n"), err
	}

	if err := windows.SetConsoleMode(entree, mode&^windows.ENABLE_ECHO_INPUT); err != nil {
		return "", err
	}
	defer func() { _ = windows.SetConsoleMode(entree, mode) }()

	fmt.Print("Mot de passe : ")
	ligne, err := bufio.NewReader(os.Stdin).ReadString('\n')
	fmt.Println()
	return strings.TrimRight(ligne, "\r\n"), err
}
