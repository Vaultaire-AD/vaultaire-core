// vaultaire_nexus — dépôt de paquets, d'images et de releases du parc Vaultaire.
//
// L'équivalent d'un WSUS ou d'un Nexus pour Linux :
//
//	dépôts RPM        servis à dnf/yum, index repodata générés
//	dépôts Debian     servis à apt, index dists/ générés, signature GPG facultative
//	registre Docker   API de distribution v2 (docker, podman, skopeo)
//	releases          binaires Vaultaire, API compatible docker-update.sh
//	fichiers          tout artefact versionné
//
// avec une interface web authentifiée par les comptes Vaultaire (LDAP) ou un
// compte local, des jetons pour les machines, et le suivi de chaque
// téléchargement.
//
// Voir README.md dans ce dossier.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"vaultaire_nexus/internal/auth"
	"vaultaire_nexus/internal/catalog"
	"vaultaire_nexus/internal/clusterlink"
	"vaultaire_nexus/internal/config"
	"vaultaire_nexus/internal/files"
	"vaultaire_nexus/internal/repos"
	"vaultaire_nexus/internal/signing"
	"vaultaire_nexus/internal/store"
	"vaultaire_nexus/internal/tlsutil"
	"vaultaire_nexus/internal/usage"
	"vaultaire_nexus/internal/web"
	"vaultaire_nexus/version"
)

func main() {
	cfgPath := flag.String("config", "/etc/vaultaire_nexus/config.yaml", "fichier de configuration YAML")
	showVersion := flag.Bool("version", false, "afficher la version et quitter")
	check := flag.Bool("check", false, "valider la configuration et quitter")
	flag.Parse()

	if *showVersion {
		fmt.Println("vaultaire_nexus", version.Complete())
		return
	}
	path := *cfgPath
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) && !isFlagSet("config") {
		path = "" // défauts seuls : mode local, /var/lib/vaultaire_nexus
	}
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("nexus : %v", err)
	}
	if *check {
		fmt.Println("configuration valide")
		return
	}
	if err := run(cfg); err != nil {
		log.Fatalf("nexus : %v", err)
	}
}

func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

func newLogger(cfg config.Config) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	if cfg.Debug {
		level = slog.LevelDebug
	}
	var w io.Writer = os.Stdout
	closeFn := func() {}
	if cfg.LogPath != "" {
		if err := os.MkdirAll(cfg.LogPath, 0o750); err == nil {
			f, err := os.OpenFile(filepath.Join(cfg.LogPath, "vaultaire_nexus.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
			if err == nil {
				w = io.MultiWriter(os.Stdout, f)
				closeFn = func() { f.Close() }
			} else {
				fmt.Fprintf(os.Stderr, "nexus : journal fichier indisponible (%v), sortie standard seule\n", err)
			}
		}
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})), closeFn, nil
}

func run(cfg config.Config) error {
	logger, closeLog, err := newLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()
	logger.Info("démarrage", "version", version.Complete(), "données", cfg.DataDir, "auth", cfg.Auth.Mode)

	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("data_dir : %w", err)
	}
	blobs, err := store.OpenBlobs(cfg.DataDir)
	if err != nil {
		return err
	}
	cat, err := catalog.Open(cfg.DataDir)
	if err != nil {
		return err
	}

	var signer *signing.GPG
	if cfg.Signing.Enable {
		signer = &signing.GPG{Binary: cfg.Signing.GPGBinary, Home: cfg.Signing.GPGHome, KeyID: cfg.Signing.KeyID}
		if err := signer.Check(); err != nil {
			return fmt.Errorf("signature GPG : %w", err)
		}
		logger.Info("signature des dépôts active", "clé", cfg.Signing.KeyID)
	}

	mgr := repos.New(&cfg, cat, blobs, signer, logger)
	for _, rc := range cfg.Repositories {
		if err := cat.EnsureRepo(rc); err != nil && !errors.Is(err, catalog.ErrRepoExists) {
			return fmt.Errorf("dépôt %s : %w", rc.Name, err)
		}
	}
	mgr.RebuildAll()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Le raccordement au cluster précède l'authentification : en mode ducky,
	// c'est lui qui vérifie les comptes.
	var link *clusterlink.Link
	var verifier auth.DuckyVerifier
	if cfg.Ducky.Enable {
		link = clusterlink.Start(ctx, cfg.Ducky, cfg.PublicURL, version.Complete(),
			time.Duration(cfg.Auth.Ducky.TimeoutSeconds)*time.Second, logger)
		verifier = link
	}

	authSvc, initial, err := auth.NewService(cfg.Auth, cfg.DataDir, logger, verifier)
	if err != nil {
		return err
	}
	if initial != "" {
		logger.Warn("compte local créé — mot de passe initial écrit dans un fichier lisible par le seul service",
			"compte", cfg.Auth.LocalAdmin.Username, "fichier", initial)
	}

	tracker, err := usage.Open(cfg.DataDir, cfg.Usage.RetentionDays, cfg.Usage.Anonymize, logger)
	if err != nil {
		return err
	}

	go tracker.Run(ctx)
	go authSvc.RefreshLoop(ctx)

	srv, err := web.New(&web.Server{
		Cfg: &cfg, Auth: authSvc, Cat: cat, Mgr: mgr, Usage: tracker, Log: logger,
		Importer: &files.Importer{Mgr: mgr, Client: files.DefaultClient(), APIURL: envOr("NEXUS_GITHUB_API", "https://api.github.com"), Token: os.Getenv("NEXUS_GITHUB_TOKEN")},
		Cluster: func() web.ClusterStatus {
			if link == nil {
				return web.ClusterStatus{}
			}
			st, detail := link.Status()
			return web.ClusterStatus{Enabled: true, State: st, Detail: detail}
		},
	})
	if err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// Pas de ReadTimeout ni de WriteTimeout globaux : une couche Docker de
		// plusieurs gigaoctets met légitimement plusieurs minutes à passer.
		MaxHeaderBytes: 64 << 10,
		ErrorLog:       slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	if cfg.TLS.Enable {
		tlsCfg, created, err := tlsutil.Load(cfg)
		if err != nil {
			return fmt.Errorf("TLS : %w", err)
		}
		if created != "" {
			logger.Warn("certificat auto-signé créé — à distribuer aux clients (docker : /etc/docker/certs.d/<hôte>:<port>/ca.crt)", "fichier", created)
		}
		httpSrv.TLSConfig = tlsCfg
		logger.Info("en écoute (HTTPS)", "adresse", cfg.Listen)
		go func() { errc <- httpSrv.ServeTLS(ln, "", "") }()
	} else {
		logger.Info("en écoute (HTTP — à placer derrière un mandataire TLS)", "adresse", cfg.Listen)
		go func() { errc <- httpSrv.Serve(ln) }()
	}

	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("arrêt demandé")
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdown)
	mgr.Flush()
	// Laisse au journal d'utilisation le temps de vider son tampon.
	time.Sleep(200 * time.Millisecond)
	logger.Info("arrêté")
	return nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
