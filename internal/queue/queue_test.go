package queue

import (
	"context"
	"testing"
	"time"
)

func TestEnqueueDequeue(t *testing.T) {
	q := New(2, 100)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if dropped := q.Enqueue([]byte("a")); dropped != 0 {
		t.Fatalf("unexpected drop: %d", dropped)
	}
	if dropped := q.Enqueue([]byte("b")); dropped != 0 {
		t.Fatalf("unexpected drop: %d", dropped)
	}
	// Next enqueue should drop the oldest due to max packets=2.
	if dropped := q.Enqueue([]byte("c")); dropped != 1 {
		t.Fatalf("expected drop=1 got %d", dropped)
	}

	pkt, err := q.Dequeue(ctx)
	if err != nil || string(pkt) != "b" {
		t.Fatalf("expected b, got %q err=%v", pkt, err)
	}
	pkt, err = q.Dequeue(ctx)
	if err != nil || string(pkt) != "c" {
		t.Fatalf("expected c, got %q err=%v", pkt, err)
	}
}

func TestDequeueCtxCancel(t *testing.T) {
	q := New(1, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := q.Dequeue(ctx); err == nil {
		t.Fatalf("expected error")
	}
}
