package worker

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestStartBackgroundCollector(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var callCount int32
	collect := func(ctx context.Context) error {
		atomic.AddInt32(&callCount, 1)
		return nil
	}

	// Start with very fast tick interval
	StartBackgroundCollector(ctx, 20*time.Millisecond, collect)

	// Allow enough time for at least 2 ticks
	time.Sleep(65 * time.Millisecond)
	cancel()

	count := atomic.LoadInt32(&callCount)
	if count < 2 {
		t.Fatalf("Expected at least 2 collector ticks, got %d", count)
	}

	// Verify it stops after context cancellation
	time.Sleep(50 * time.Millisecond)
	countAfterCancel := atomic.LoadInt32(&callCount)
	if countAfterCancel > count+1 {
		t.Fatalf("Collector continued running after cancellation: initial %d, after %d", count, countAfterCancel)
	}
}
