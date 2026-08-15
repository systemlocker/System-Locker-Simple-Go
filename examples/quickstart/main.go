// Command quickstart shows the smallest working Simple integration.
package main

import (
	"context"
	"fmt"

	"github.com/systemlocker/system-locker-simple-go"
)

func main() {
	config := simple.DefaultConfig()
	config.SystemID = "abcdefghijklmnopqrst" // from the dashboard
	config.Version = "1.0.0"
	// config.HWID stays "1" unless you want device locking.

	client, _ := simple.NewClient(config)

	ok, err := client.AuthenticateWithKey(context.Background(), "SL-XXXX-XXXX-XXXX")
	if err != nil {
		fmt.Println("check failed:", err)
		return
	}
	if !ok {
		fmt.Println("license rejected")
		return
	}
	fmt.Println("license ok — run your protected action")

	// Server-side variables, expiration, and self-service HWID resets:
	expiration, _ := client.KeyExpirationForKey(context.Background(), "SL-XXXX-XXXX-XXXX")
	fmt.Println("expires:", expiration.ExpiresAt)

	variable, _ := client.GetVariable(context.Background(), "feature_flags")
	if variable.Found {
		fmt.Println("feature_flags =", variable.Value)
	}
}
