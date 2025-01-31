// SPDX-License-Identifier: MIT OR Apache-2.0

package batcher

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"

	"github.com/khulnasoft/fanal/types"
)

func TestElasticsearchBatcher(t *testing.T) {
	const (
		batchSize     = 1234
		testCount     = 100
		flushInterval = 300 * time.Millisecond
	)

	// Just to emulated similar payload for testing, not strictly needed
	type eSPayload struct {
		types.KhulnasoftPayload
		Timestamp time.Time `json:"@timestamp"`
	}

	marshalFunc := func(payload types.KhulnasoftPayload) ([]byte, error) {
		return json.Marshal(eSPayload{KhulnasoftPayload: payload, Timestamp: payload.Time})
	}

	var wantBatches, gotBatches [][]byte

	var mx sync.Mutex
	batcher := New(
		WithBatchSize(batchSize),
		WithFlushInterval(500*time.Millisecond),
		WithMarshal(marshalFunc),
		WithCallback(func(khulnasoftPayloads []types.KhulnasoftPayload, data []byte) {
			mx.Lock()
			defer mx.Unlock()
			gotBatches = append(gotBatches, data)
		}))

	var currentBatch []byte
	for i := 0; i < testCount; i++ {
		payload := types.KhulnasoftPayload{UUID: uuid.Must(uuid.NewV7()).String()}
		data, err := marshalFunc(payload)
		if err != nil {
			t.Fatal(err)
		}

		if len(currentBatch)+len(data) > batchSize {
			wantBatches = append(wantBatches, currentBatch)
			currentBatch = nil
		}

		currentBatch = append(currentBatch, data...)

		err = batcher.Push(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	wantBatches = append(wantBatches, currentBatch)

	// give it time to flush
	time.Sleep(flushInterval * 2)

	mx.Lock()
	defer mx.Unlock()
	diff := cmp.Diff(wantBatches, gotBatches)
	if diff != "" {
		t.Fatal(diff)
	}

}
