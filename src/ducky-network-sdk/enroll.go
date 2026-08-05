package duckynetwork

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

// EnrollError est un refus d'enrôlement renvoyé par le core.
type EnrollError struct{ Code string }

func (e EnrollError) Error() string { return "enrôlement refusé : " + e.Code }

// Enroll génère une paire de clés et fait enregistrer la publique auprès du core.
//
// # Ce que le client ne choisit PAS
//
// Ni son identifiant machine, ni son type. Les deux viennent du core : le premier
// est attribué, le second est porté par la clé d'enrôlement. Un client qui
// pourrait annoncer son type n'aurait qu'à s'enrôler pour se donner les
// privilèges qu'il veut.
//
// # La clé privée ne quitte jamais cet hôte
//
// Elle est générée ici et n'est jamais transmise. C'est toute la différence avec
// l'enrôlement d'un agent, dont le core produit la paire et livre la privée avec
// sa configuration.
func Enroll(coreAddress, serverPublicKeyPEM, enrollmentKey, label string) (Identity, error) {
	if strings.TrimSpace(enrollmentKey) == "" {
		return Identity{}, fmt.Errorf("clé d'enrôlement absente")
	}

	privatePEM, publicPEM, err := GenerateKeyPair()
	if err != nil {
		return Identity{}, err
	}

	conn, err := dialCore(coreAddress)
	if err != nil {
		return Identity{}, err
	}
	defer func() { _ = conn.Close() }()

	// La clé publique voyage en base64 : le format de trame est ligne à ligne,
	// et un PEM en contient plusieurs.
	request := Frame{
		Code:    Trame01_03,
		Target:  TargetCore,
		Content: enrollmentKey + "\n" + base64.StdEncoding.EncodeToString([]byte(publicPEM)) + "\n" + label,
	}
	cipher, err := encryptRSA(serverPublicKeyPEM, request.Build())
	if err != nil {
		return Identity{}, fmt.Errorf("chiffrement de la demande d'enrôlement : %w", err)
	}
	if err := writePacket(conn, cipher); err != nil {
		return Identity{}, fmt.Errorf("envoi de 01_03 : %w", err)
	}

	raw, err := readPacket(conn)
	if err != nil {
		return Identity{}, fmt.Errorf("lecture de la réponse d'enrôlement : %w", err)
	}

	// Un refus arrive EN CLAIR : le core n'a pas forcément de clé publique
	// exploitable à ce stade, c'est précisément ce qui peut avoir échoué. On
	// tente donc de lire le refus avant de déchiffrer.
	if frame, err := ParseFrame(string(raw)); err == nil && (frame.Code == Trame01_05 || frame.Code == Trame01_06) {
		return Identity{}, EnrollError{Code: frame.Line(0)}
	}

	// Une acceptation est chiffrée avec la clé publique qu'on vient de
	// soumettre : la déchiffrer PROUVE que nous détenons la privée
	// correspondante. C'est le même mécanisme que 01_02, et il rend un défi
	// explicite inutile.
	plain, err := decryptRSA(privatePEM, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("réponse d'enrôlement illisible : %w", err)
	}
	frame, err := ParseFrame(plain)
	if err != nil {
		return Identity{}, err
	}
	if frame.Code != Trame01_04 {
		return Identity{}, fmt.Errorf("réponse inattendue à l'enrôlement : %s", frame.Code)
	}

	computeurID := frame.Line(0)
	if computeurID == "" {
		return Identity{}, fmt.Errorf("le core n'a attribué aucun identifiant")
	}

	return Identity{
		ComputeurID: computeurID,
		ClientType:  frame.Line(1),
		PrivateKey:  privatePEM,
		PublicKey:   publicPEM,
		EnrolledAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}
