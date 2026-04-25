// rs is the standalone resource-server binary run inside docker compose
// alongside Keycloak. It exposes POST /exec/greet on PORT (default 3000).
package main

import (
	"log"
	"os"
	"strconv"

	"github.com/chh/keycloak-agent-auth/examples/go/internal/rs"
)

func main() {
	port := 3000
	if v := os.Getenv("PORT"); v != "" {
		parsed, err := strconv.Atoi(v)
		if err != nil {
			log.Fatalf("[rs-standalone] invalid PORT=%q: %v", v, err)
		}
		port = parsed
	}

	_, err := rs.StartOn(port, map[string]rs.CapabilityHandler{
		"/exec/greet": func(args map[string]any) map[string]any {
			name, _ := args["name"].(string)
			if name == "" {
				name = "world"
			}
			return map[string]any{"greeting": "Hello, " + name + "!"}
		},
	})
	if err != nil {
		log.Fatalf("[rs-standalone] fatal: %v", err)
	}
	log.Println("[rs-standalone] ready")

	// Block forever.
	select {}
}
