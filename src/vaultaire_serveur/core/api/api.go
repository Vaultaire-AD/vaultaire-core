package api

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
	"vaultaire/core/auth/ratelimit"
	"vaultaire/core/command"
	"vaultaire/core/database"
	dbusers "vaultaire/core/database/db_users"
	"vaultaire/core/global/security"
	"vaultaire/core/logs"
	"vaultaire/core/permission"
	"vaultaire/core/storage"
	duckykey "vaultaire/ducky-network/key_management"

	"golang.org/x/crypto/ssh"
)

// CommandRequest représente la requête JSON du client
type CommandRequest struct {
	Username string `json:"username"`
	Command  string `json:"command"`
	Nonce    string `json:"nonce"`
	// Timestamp est l'heure d'émission en secondes Unix. Il entre dans le corps
	// signé : sans lui, une requête capturée resterait valide pour toujours
	// puisque la signature ne dit rien de la date. Voir replay.go.
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"` // en base64
}

// CommandResponse est renvoyée au client
type CommandResponse struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// ===================== HANDLER PRINCIPAL =====================

// Bornes de l'API de commande (TO-DO 102).
//
// Le port est ouvert à tous et l'authentification EST la signature : rien ne
// filtre une requête avant le travail coûteux — lecture du corps, deux
// lectures en base, une vérification de signature par clé du compte visé.
// Trois bornes, dans l'ordre où elles s'appliquent, toutes AVANT ce travail.
const (
	// tailleMaxCorps borne le corps lu. Une commande est une ligne de `vlt` :
	// 64 Kio en laissent cent fois la place. Sans borne, le décodage JSON
	// acceptait ce que le réseau livrait en 30 s de ReadTimeout — plusieurs
	// gigaoctets par requête en vol, avant toute authentification.
	tailleMaxCorps = 64 << 10

	// messageRefus est LE message de tout refus d'authentification : compte
	// inconnu, révoqué, sans clé ou signature fausse. Des messages distincts
	// diraient lequel, donc si le nom existe. Le détail va au journal, que seul
	// l'exploitant lit.
	messageRefus = "authentification refusée"
)

// debitAPI freine chaque source sur le VOLUME, avant même la lecture du corps.
//
// Le barème par défaut laisse passer une rafale de 100 commandes d'un coup,
// puis 20 par seconde soutenues : un intégrateur qui crée cent comptes ne sent
// rien, un flot continu est ramené à un coût borné. Réglable par
// api.limite_rafale et api.limite_par_seconde.
var debitAPI = ratelimit.NouveauDebit("api", storage.API_Limite_Rafale, storage.API_Limite_Par_Seconde)

// Recherches en base, remplaçables par les tests : le handler s'y éprouve sans
// base de données.
var (
	chercherCompte = fetchUserID
	chercherCles   = dbusers.GetUserKeys
)

func commandHandler(w http.ResponseWriter, r *http.Request) {
	requestID := r.Header.Get("X-Request-ID")
	source := ratelimit.SourceHTTP(r)

	// 1. Le VOLUME, par source, avant de lire quoi que ce soit.
	if ok, reste := debitAPI.Prendre(source); !ok {
		refuserTropTot(w, reste)
		return
	}
	// 2. Les ÉCHECS répétés de cette source — les mêmes compteurs que le
	// portail et LDAP. Par source SEULE : une signature ne se devine pas, il
	// n'y a pas de mot de passe à protéger côté compte, et un compteur par
	// compte permettrait à n'importe qui de freiner l'intégrateur d'un tiers
	// en signant faux à son nom.
	if ok, reste := ratelimit.Autorise("", source); !ok {
		refuserTropTot(w, reste)
		return
	}

	// 3. Le corps, borné.
	req, err := decodeRequest(w, r)
	if err != nil {
		logRequest(requestID, 0, req, "", err)
		var tropGros *http.MaxBytesError
		if errors.As(err, &tropGros) {
			http.Error(w, fmt.Sprintf("requête trop volumineuse : %d octets au plus", tailleMaxCorps),
				http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, err := authentifier(req)
	if err != nil {
		ratelimit.Echec("", source)
		logRequest(requestID, userID, req, "", err)
		http.Error(w, messageRefus, http.StatusUnauthorized)
		return
	}
	ratelimit.Reussite("", source)

	// Fraîcheur vérifiée APRÈS la signature, et c'est volontaire : l'horodatage
	// et le nonce font partie du corps signé, les contrôler avant reviendrait à
	// se prononcer sur des valeurs que n'importe qui peut écrire.
	if err := checkFreshness(req); err != nil {
		logRequest(requestID, userID, req, "", err)
		http.Error(w, "Requête rejetée : "+err.Error(), http.StatusUnauthorized)
		return
	}

	result := command.ExecuteCommand(req.Command, req.Username)
	logRequest(requestID, userID, req, result, nil)
	writeJSON(w, CommandResponse{Result: result})
}

// authentifier vérifie la signature d'une requête, et rend l'identifiant du
// compte.
//
// # Le même chemin pour tous les refus (TO-DO 102)
//
// Compte inconnu, révoqué, sans clé, signature fausse : chacun faisait sortir
// le handler à une étape différente, avec un message différent. Le message et
// le temps de réponse disaient donc lequel — et par là, si le nom existait.
//
// Désormais toutes les étapes sont parcourues quoi qu'il arrive : la base est
// lue deux fois, la signature est vérifiée (contre une clé-leurre si le compte
// n'en a pas, voir leurre.go), et le refus n'est décidé qu'à la fin.
func authentifier(req *CommandRequest) (int, error) {
	nom := strings.TrimSpace(req.Username)

	// KILL SWITCH. Un compte révoqué conserve ses clés SSH en base : sans ce
	// refus, sa signature resterait parfaitement valide et l'API continuerait
	// de lui obéir. Noté ici, décidé à la fin.
	revoque := permission.IsRevoked(nom)

	userID, errCompte := chercherCompte(nom)
	if errCompte != nil {
		userID = 0
	}
	// Lue même pour un compte inconnu : la requête de plus coûte ce que coûte
	// celle d'un compte réel, et l'identifiant 0 ne désigne personne.
	pubKeys, errCles := chercherCles(userID)
	if errCompte != nil || errCles != nil {
		pubKeys = nil
	}

	bodyToVerify, err := buildSignedBody(req)
	if err != nil {
		return userID, err
	}
	signee := verifySignature(pubKeys, bodyToVerify, req.Signature)

	switch {
	case errCompte != nil:
		return 0, fmt.Errorf("compte inconnu : %v", errCompte)
	case revoque:
		return userID, fmt.Errorf("compte révoqué")
	case errCles != nil:
		return userID, fmt.Errorf("lecture des clés : %v", errCles)
	case len(pubKeys) == 0:
		return userID, fmt.Errorf("aucune clé publique enregistrée")
	case !signee:
		return userID, fmt.Errorf("signature invalide")
	}
	return userID, nil
}

// refuserTropTot répond à une requête freinée : 429, et le délai en secondes
// entières, arrondi au-dessus — un client qui relit Retry-After et réessaie
// pile à l'échéance ne doit pas retomber juste avant.
func refuserTropTot(w http.ResponseWriter, reste time.Duration) {
	secondes := int(math.Ceil(reste.Seconds()))
	if secondes < 1 {
		secondes = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secondes))
	http.Error(w, fmt.Sprintf("trop de requêtes : réessayer dans %d s", secondes),
		http.StatusTooManyRequests)
}

// logRequest logs one API command line with request_id and user_id (specific errors are already logged by decodeRequest etc.).
func logRequest(requestID string, userID int, req *CommandRequest, result string, err error) {
	username := "<unknown>"
	commandStr := "<empty>"
	if req != nil {
		username = req.Username
		commandStr = req.Command
	}
	level := "INFO"
	msg := "api: command user=" + username + " command=" + commandStr + " status=success"
	if err != nil {
		level = "ERROR"
		msg = "api: command failed user=" + username + " error=" + err.Error()
	}
	meta := logs.WithMeta(requestID, strconv.Itoa(userID))
	if meta == nil && userID > 0 {
		meta = logs.UserMeta(userID)
	}
	logs.Write_LogCodeMeta(level, logs.CodeNone, msg, meta)
}

// ===================== SOUS-FONCTIONS =====================

// decodeRequest lit et parse la requête JSON, sans lire au-delà de
// tailleMaxCorps.
func decodeRequest(w http.ResponseWriter, r *http.Request) (*CommandRequest, error) {
	var req CommandRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, tailleMaxCorps)).Decode(&req); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPIDecode, "api: JSON decode failed: "+err.Error())
		return nil, err
	}
	return &req, nil
}

// fetchUserID retourne l’ID utilisateur depuis son username
func fetchUserID(username string) (int, error) {
	return dbusers.Get_User_ID_By_Username(database.GetDatabase(), strings.TrimSpace(username))
}

// buildSignedBody reconstruit le JSON que le client a signé
func buildSignedBody(req *CommandRequest) ([]byte, error) {
	body, err := json.Marshal(struct {
		Command   string `json:"command"`
		Username  string `json:"username"`
		Nonce     string `json:"nonce"`
		Timestamp int64  `json:"timestamp"`
	}{
		Command:   req.Command,
		Username:  req.Username,
		Nonce:     req.Nonce,
		Timestamp: req.Timestamp,
	})
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signed body build failed: "+err.Error())
		return nil, err
	}
	return body, nil
}

// verifySignature vérifie la signature avec toutes les clés.
//
// Sans clé — compte inconnu, révoqué, sans clé enregistrée —, la signature est
// vérifiée contre une clé-leurre du même type, pour que ce refus coûte ce que
// coûte celui d'une signature fausse. Voir leurre.go.
func verifySignature(pubKeys []storage.PublicKey, body []byte, sigB64 string) bool {
	sigRaw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signature base64 decode failed: "+err.Error())
		return false
	}

	var sig ssh.Signature
	if err := ssh.Unmarshal(sigRaw, &sig); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: signature SSH unmarshal failed: "+err.Error())
		return false
	}

	if len(pubKeys) == 0 {
		if leurre := leurrePour(sig.Format); leurre != nil {
			_ = leurre.Verify(body, &sig)
		}
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: no public key validated the signature")
		return false
	}

	success := false

	for i, k := range pubKeys {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.Key))
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeAPISign, fmt.Sprintf("api: public key #%d invalid: %s", i, err))
			continue
		}

		if err := pub.Verify(body, &sig); err != nil {
			logs.Write_Log("DEBUG", fmt.Sprintf("api: public key #%d verify failed: %s", i, err))
		} else {
			success = true
			break
		}
	}

	if !success {
		logs.Write_LogCode("ERROR", logs.CodeAPISign, "api: no public key validated the signature")
	}

	return success
}

// writeJSON renvoie la réponse JSON
func writeJSON(w http.ResponseWriter, resp CommandResponse) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPIDecode, "api: JSON write failed: "+err.Error())
	}
}

// ===================== SERVEUR API =====================

func StartAPI() {
	preparerLeurres()
	// Le barème vient de la configuration, lue après l'initialisation du
	// paquet.
	debitAPI.Regler(storage.API_Limite_Rafale, storage.API_Limite_Par_Seconde)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/command", commandHandler)

	certPEM, keyPEM, err := duckykey.GetCertificatePEMFromDB(duckykey.APIServerCertName)
	if err != nil {
		certPEM, keyPEM, err = security.GenerateSelfSignedCertPEM()
		if err != nil {
			logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: certificate generation failed: "+err.Error())
			return
		}
		if errSave := duckykey.SaveCertificateToDB(duckykey.APIServerCertName, "tls_cert", "Certificat TLS API REST", certPEM, keyPEM); errSave != nil {
			certPEM, keyPEM, err = duckykey.GetCertificatePEMFromDB(duckykey.APIServerCertName)
			if err != nil {
				logs.Write_LogCode("ERROR", logs.CodeCertLoad, "api: certificate load from database failed: "+err.Error())
				return
			}
		}
	}

	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: TLS certificate load failed: "+err.Error())
		return
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}

	server := &http.Server{
		Addr:      ":" + strconv.Itoa(storage.API_Port),
		Handler:   mux,
		TLSConfig: tlsConfig,
		// Mêmes délais que l'interface web, et pour la même raison : sans eux
		// une connexion lente retient une goroutine sans limite de temps.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logs.Write_Log("INFO", "api: REST HTTPS listening on port "+strconv.Itoa(storage.API_Port))

	listener, err := tls.Listen("tcp", ":"+strconv.Itoa(storage.API_Port), tlsConfig)
	if err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: TLS listen failed: "+err.Error())
		return
	}
	if err := server.Serve(listener); err != nil {
		logs.Write_LogCode("ERROR", logs.CodeAPITLS, "api: server serve failed: "+err.Error())
	}
}
