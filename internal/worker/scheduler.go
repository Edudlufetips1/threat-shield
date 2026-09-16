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
		log.Println("Running initial collection task...")
		if err := collect(ctx); err != nil {
			log.Printf("Connection initialization failed: %v", err)
		}
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
