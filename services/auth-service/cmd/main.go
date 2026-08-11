package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/api"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/config"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/database"
	"github.com/vistasecurity/vistaplatform/auth-service/internal/middleware"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/security/jwtkeys"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize database
	db, err := database.Connect(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Initialize the BYPASSRLS (crypto_bypass) connection used by the
	// deliberately cross-tenant login/registration paths (where the tenant is
	// the query OUTPUT). Reads BYPASS_DATABASE_URL, falling back to
	// DATABASE_URL when unset — so pre-flip both handles resolve to the same
	// connection and behavior is unchanged. After the RLS role split,
	// DATABASE_URL → crypto_app (subject to RLS) and BYPASS_DATABASE_URL →
	// crypto_bypass (BYPASSRLS).
	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to connect to bypass database: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	// Initialize Redis
	redis, err := database.ConnectRedis(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer func() { _ = redis.Close() }()

	// Initialize rate limiter
	rateLimiter := middleware.NewRateLimiter(
		redis,
		cfg.RateLimitDefault,
		cfg.RateLimitWindow,
		cfg.RateLimitLogin,
	)

	log.Printf("auth-service edition: %s", edition())

	// Seed platform SSO providers from env vars (Google/Microsoft for
	// registration). Enterprise only — Core has no social signup, so the hook
	// is nil and nothing is seeded.
	if hooks.SeedPlatformSSOProviders != nil {
		hooks.SeedPlatformSSOProviders(db)
	}

	// Set Gin mode
	if cfg.Environment == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize router
	router := api.SetupRouter(cfg, db, bypassDB, redis, rateLimiter, hooks.Router)

	// Health check server (HTTP, port 8080)
	healthRouter := gin.New()
	healthRouter.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "healthy",
			"service": "auth-service",
			"version": version.Get(),
		})
	})

	// JWKS on the PLAINTEXT listener too.
	//
	// Under serviceMtls the real API moves to :8443 and demands a client
	// certificate, so an in-cluster verifier fetching JWKS from :8443 would need
	// mTLS plumbing in its HTTP client — the exact trap that made both platform
	// agents report offline once before (see the S2S note in CLAUDE.md).
	//
	// The JWKS document is PUBLIC key material. There is nothing to protect, and
	// requiring a client certificate to fetch the keys you need in order to
	// authenticate is a circularity with no security value. So it is served
	// beside /health, where every service can reach it as
	// http://auth-service:8080/.well-known/jwks.json regardless of mTLS state.
	// It remains available on the API listener and through the edge as well.
	if s := api.JWTSigner(); s != nil {
		healthRouter.GET(jwtkeys.JWKSPath, func(c *gin.Context) {
			jwtkeys.ServeJWKS(c.Writer, s)
		})
	}

	healthServer := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           healthRouter,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// API server (HTTPS with mTLS, port 8443)
	var apiServer *http.Server
	if cfg.UseMTLS {
		apiServer, err = sharedhttp.NewMTLSServer(
			cfg.ServiceCertPath,
			cfg.ServiceKeyPath,
			cfg.PlatformCACertPath,
			router,
		)
		if err != nil {
			log.Fatalf("Failed to create mTLS server: %v", err)
		}
		apiServer.Addr = ":" + cfg.TLSPort
		apiServer.ReadHeaderTimeout = 5 * time.Second
		apiServer.ReadTimeout = 10 * time.Second
		apiServer.WriteTimeout = 15 * time.Second
		apiServer.IdleTimeout = 60 * time.Second
	} else {
		// Fallback to HTTP if mTLS disabled
		apiServer = &http.Server{
			Addr:              ":" + cfg.Port,
			Handler:           router,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
	}

	// Start health check server (only when mTLS is enabled - API server on different port)
	// When mTLS is disabled, API server includes /health endpoint on same port
	if cfg.UseMTLS {
		go func() {
			log.Printf("Health check server starting on port %s", cfg.Port)
			if err := healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start health server: %v", err)
			}
		}()
	}

	// Start API server
	go func() {
		if cfg.UseMTLS {
			log.Printf("Auth service API server starting on port %s (mTLS)", cfg.TLSPort)
			if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		} else {
			log.Printf("Auth service API server starting on port %s (HTTP - includes /health)", cfg.Port)
			if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Failed to start API server: %v", err)
			}
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down auth service...")

	// Give outstanding requests 30 seconds to complete
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown both servers
	if err := healthServer.Shutdown(ctx); err != nil {
		log.Printf("Health server forced to shutdown: %v", err)
	}
	if err := apiServer.Shutdown(ctx); err != nil {
		log.Printf("API server forced to shutdown: %v", err)
	}

	log.Println("Auth service stopped")
}
