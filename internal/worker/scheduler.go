package worker

import (
	"context"
	"log"
	"time"
)

func StartBackgroundCollector(ctx context.Context, interval time.Duration, collect func(context.Context) error) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				err := collect(ctx)
				if err != nil {
					log.Printf("Failed to collect data: %v", err)
					continue
				}
			case <-ctx.Done():
				return
			}
		}
	}()
}
