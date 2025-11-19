package queue

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed indicates the queue was closed and no more items will be delivered.
var ErrClosed = errors.New("queue closed")

// PacketQueue implements a bounded FIFO with drop-oldest semantics.
type PacketQueue struct {
	mu         sync.Mutex
	cond       *sync.Cond
	packets    [][]byte
	totalBytes int
	maxPackets int
	maxBytes   int
	closed     bool
}

func New(maxPackets, maxBytes int) *PacketQueue {
	pq := &PacketQueue{
		maxPackets: maxPackets,
		maxBytes:   maxBytes,
	}
	pq.cond = sync.NewCond(&pq.mu)
	return pq
}

// Enqueue adds a packet, dropping oldest until limits satisfied. Returns number dropped.
func (q *PacketQueue) Enqueue(pkt []byte) int {
	return q.enqueue(pkt, false)
}

// RequeueFront pushes a packet to the front of the queue (used when retrying sends).
func (q *PacketQueue) RequeueFront(pkt []byte) int {
	return q.enqueue(pkt, true)
}

func (q *PacketQueue) enqueue(pkt []byte, front bool) int {
	q.mu.Lock()
	defer func() {
		q.cond.Signal()
		q.mu.Unlock()
	}()

	if q.closed {
		return 0
	}

	cp := make([]byte, len(pkt))
	copy(cp, pkt)
	if front {
		q.packets = append([][]byte{cp}, q.packets...)
	} else {
		q.packets = append(q.packets, cp)
	}
	q.totalBytes += len(cp)

	dropped := 0
	for (q.maxPackets > 0 && len(q.packets) > q.maxPackets) || (q.maxBytes > 0 && q.totalBytes > q.maxBytes) {
		oldest := q.packets[0]
		q.packets = q.packets[1:]
		q.totalBytes -= len(oldest)
		dropped++
	}
	return dropped
}

// Dequeue blocks until a packet is available, the queue is closed, or ctx is done.
func (q *PacketQueue) Dequeue(ctx context.Context) ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	ctxSignaled := false
	for {
		if len(q.packets) > 0 {
			pkt := q.packets[0]
			q.packets = q.packets[1:]
			q.totalBytes -= len(pkt)
			return pkt, nil
		}
		if q.closed {
			return nil, ErrClosed
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !ctxSignaled && ctx.Done() != nil {
			ctxSignaled = true
			go func() {
				<-ctx.Done()
				q.cond.Broadcast()
			}()
		}
		q.cond.Wait()
	}
}

// Close stops the queue and wakes all waiters.
func (q *PacketQueue) Close() {
	q.mu.Lock()
	defer func() {
		q.closed = true
		q.cond.Broadcast()
		q.mu.Unlock()
	}()
}

// Len returns the current length of the queue.
func (q *PacketQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.packets)
}
