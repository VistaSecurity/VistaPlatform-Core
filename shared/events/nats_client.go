package events

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// NATSClient wraps NATS connection with retry logic, health checks,
// and automatic JetStream stream provisioning.
type NATSClient struct {
	conn      *nats.Conn
	js        nats.JetStreamContext
	url       string
	connected bool
	mu        sync.RWMutex
	stop      chan struct{}
}

// NewNATSClient creates a new NATS client with connection management.
// The url parameter is resolved in this order:
//  1. Explicit url argument
//  2. NATS_URL environment variable
//
// An empty url with no NATS_URL env var returns an error.
func NewNATSClient(url string) (*NATSClient, error) {
	if url == "" {
		url = os.Getenv("NATS_URL")
		if url == "" {
			return nil, fmt.Errorf("NATS URL not configured: set NATS_URL environment variable")
		}
	}

	client := &NATSClient{
		url:  url,
		stop: make(chan struct{}),
	}

	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	// Provision JetStream streams
	if client.js != nil {
		if err := EnsureStreams(client.js, DefaultStreams); err != nil {
			log.Printf("[NATS] Warning: failed to provision streams: %v", err)
		}
	}

	// Start connection monitor
	go client.monitorConnection()

	return client, nil
}

// connect establishes connection to NATS with retry logic
func (c *NATSClient) connect() error {
	maxRetries := 5
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		opts := []nats.Option{
			nats.Name("crypto-inventory-events"),
			nats.ReconnectWait(2 * time.Second),
			nats.MaxReconnects(-1),
			nats.DisconnectErrHandler(func(nc *nats.Conn, err error) {
				c.mu.Lock()
				c.connected = false
				c.mu.Unlock()
				if err != nil {
					log.Printf("[NATS] Disconnected: %v", err)
				}
			}),
			nats.ReconnectHandler(func(nc *nats.Conn) {
				c.mu.Lock()
				c.connected = true
				c.mu.Unlock()
				log.Printf("[NATS] Reconnected to %s", nc.ConnectedUrl())
			}),
			nats.ClosedHandler(func(nc *nats.Conn) {
				c.mu.Lock()
				c.connected = false
				c.mu.Unlock()
				log.Printf("[NATS] Connection closed")
			}),
		}

		// v0.1.2+: append mTLS options when NATS_TLS_* env vars are set.
		// In v0.1.1 these env vars are unset and the chart's NATS_TOKEN
		// auth path stays in effect. See shared/events/nats_tls.go.
		if tlsOpts := natsTLSOptionsFromEnv(); tlsOpts != nil {
			opts = append(opts, tlsOpts...)
		}

		conn, err := nats.Connect(c.url, opts...)
		if err == nil {
			c.mu.Lock()
			c.conn = conn
			c.connected = true
			c.mu.Unlock()

			// Initialize JetStream context
			js, jsErr := conn.JetStream()
			if jsErr != nil {
				log.Printf("[NATS] Warning: JetStream not available: %v", jsErr)
			} else {
				c.mu.Lock()
				c.js = js
				c.mu.Unlock()
			}

			log.Printf("[NATS] Connected to %s", conn.ConnectedUrl())
			return nil
		}

		if i < maxRetries-1 {
			log.Printf("[NATS] Connection attempt %d/%d failed: %v, retrying in %v...", i+1, maxRetries, err, retryDelay)
			time.Sleep(retryDelay)
			retryDelay *= 2
		} else {
			return fmt.Errorf("failed to connect after %d attempts: %w", maxRetries, err)
		}
	}

	return fmt.Errorf("failed to connect to NATS")
}

// monitorConnection monitors connection health and attempts reconnection if needed
func (c *NATSClient) monitorConnection() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.stop:
			return
		case <-ticker.C:
			c.mu.RLock()
			connected := c.connected && c.conn != nil && c.conn.IsConnected()
			c.mu.RUnlock()

			if !connected {
				log.Printf("[NATS] Connection lost, attempting to reconnect...")
				if err := c.connect(); err != nil {
					log.Printf("[NATS] Reconnection failed: %v", err)
				}
			}
		}
	}
}

// Conn returns the underlying NATS connection
func (c *NATSClient) Conn() *nats.Conn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn
}

// JetStream returns the JetStream context
func (c *NATSClient) JetStream() nats.JetStreamContext {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.js
}

// IsConnected returns whether the client is currently connected
func (c *NATSClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.connected && c.conn != nil && c.conn.IsConnected()
}

// HealthCheck performs a health check on the NATS connection
func (c *NATSClient) HealthCheck(ctx context.Context) error {
	if !c.IsConnected() {
		return fmt.Errorf("NATS client not connected")
	}

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil || !conn.IsConnected() {
		return fmt.Errorf("NATS connection is not active")
	}

	return nil
}

// Close closes the NATS connection and stops the monitor goroutine.
func (c *NATSClient) Close() {
	close(c.stop)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.connected = false
		log.Printf("[NATS] Connection closed")
	}
}

// GracefulShutdown drains in-flight messages then closes the connection.
func (c *NATSClient) GracefulShutdown(ctx context.Context) error {
	close(c.stop)

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		if err := c.conn.Drain(); err != nil {
			return fmt.Errorf("failed to drain NATS connection: %w", err)
		}
		c.connected = false
		log.Printf("[NATS] Gracefully shut down")
	}

	return nil
}

// Publish publishes a message to a NATS subject via JetStream with a
// deduplication message ID. Falls back to core NATS if JetStream is unavailable.
func (c *NATSClient) Publish(subject string, data []byte, msgID string) error {
	if !c.IsConnected() {
		return fmt.Errorf("NATS client not connected")
	}

	c.mu.RLock()
	js := c.js
	conn := c.conn
	c.mu.RUnlock()

	if js != nil {
		opts := []nats.PubOpt{}
		if msgID != "" {
			opts = append(opts, nats.MsgId(msgID))
		}
		_, err := js.Publish(subject, data, opts...)
		if err == nil {
			return nil
		}
		log.Printf("[NATS] JetStream publish to %s failed, falling back to core NATS: %v", subject, err)
	}

	if conn == nil {
		return fmt.Errorf("NATS connection not available")
	}
	return conn.Publish(subject, data)
}
