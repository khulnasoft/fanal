// SPDX-License-Identifier: MIT OR Apache-2.0

package batcher

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"

	"github.com/khulnasoft/fanal/types"
)

const (
	defaultBatchSize     = 5 * 1024 * 1024 // max batch size in bytes, 5MB by default
	defaultFlushInterval = time.Second
)

type CallbackFunc func(khulnasoftPayloads []types.KhulnasoftPayload, serialized []byte)

type OptionFunc func(b *Batcher)

// MarshalFunc is a callback that allows the user of the batcher to overwrite the default JSON marshalling
type MarshalFunc func(payload types.KhulnasoftPayload) ([]byte, error)

// Batcher A simple generic implementation of Khulnasoft payloads batching
// Batching can be configured by the batchSize which is a max number of payloads in the batch or the flushInterval.
// The callback function is called when the number of payloads reaches the batchSize or upon the flushInterval
type Batcher struct {
	batchSize     int
	flushInterval time.Duration

	callbackFn CallbackFunc
	marshalFn  MarshalFunc

	mx sync.Mutex

	pending bytes.Buffer
	// Keeping the original payloads for errors resolution
	pendingPayloads []types.KhulnasoftPayload

	curTimer *time.Timer
}

func New(opts ...OptionFunc) *Batcher {
	b := &Batcher{
		batchSize:     defaultBatchSize,
		flushInterval: defaultFlushInterval,
		callbackFn:    func(khulnasoftPayloads []types.KhulnasoftPayload, batch []byte) {},
		marshalFn:     jsonMarshal,
	}

	for _, opt := range opts {
		opt(b)
	}

	return b
}

func WithBatchSize(sz int) OptionFunc {
	return func(b *Batcher) {
		b.batchSize = sz
	}
}

func WithFlushInterval(interval time.Duration) OptionFunc {
	return func(b *Batcher) {
		b.flushInterval = interval
	}
}

func WithCallback(cb CallbackFunc) OptionFunc {
	return func(b *Batcher) {
		b.callbackFn = cb
	}
}

func WithMarshal(fn MarshalFunc) OptionFunc {
	return func(b *Batcher) {
		b.marshalFn = fn
	}
}

func (b *Batcher) Push(khulnasoftpayload types.KhulnasoftPayload) error {
	b.mx.Lock()
	defer b.mx.Unlock()

	data, err := b.marshalFn(khulnasoftpayload)
	if err != nil {
		return err
	}
	if b.pending.Len() == 0 {
		b.scheduleFlushInterval()
	} else if b.pending.Len()+len(data) > b.batchSize {
		b.flush()
		b.scheduleFlushInterval()
	}
	_, _ = b.pending.Write(data)
	b.pendingPayloads = append(b.pendingPayloads, khulnasoftpayload)
	return nil
}

func (b *Batcher) scheduleFlushInterval() {
	if b.curTimer != nil {
		b.curTimer.Stop()
	}
	b.curTimer = time.AfterFunc(b.flushInterval, b.flushOnTimer)
}

func (b *Batcher) flushOnTimer() {
	b.mx.Lock()
	defer b.mx.Unlock()
	b.flush()
}

func (b *Batcher) flush() {
	if b.pending.Len() == 0 {
		return
	}

	serialized := b.pending.Bytes()
	khulnasoftPayloads := b.pendingPayloads

	b.pending = bytes.Buffer{}
	b.pendingPayloads = nil
	b.callbackFn(khulnasoftPayloads, serialized)
}

// jsonMarshal default marshal function
func jsonMarshal(payload types.KhulnasoftPayload) ([]byte, error) {
	return json.Marshal(payload)
}
