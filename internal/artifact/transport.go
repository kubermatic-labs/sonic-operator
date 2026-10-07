// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const SocketPath = "/run/sonic-operator-artifacts/supervisor.sock"
const MaxWireBytes = 180 << 20

func Decode(data []byte, out any) error {
	if len(data) > MaxWireBytes {
		return fmt.Errorf("artifact message too large")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return fmt.Errorf("artifact message must be an object")
	}
	if unambiguousJSON(data) != nil {
		return fmt.Errorf("invalid or ambiguous artifact message")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("invalid artifact message")
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing artifact message")
	}
	return nil
}
func (e *Engine) Execute(ctx context.Context, r Request) (*Result, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := MetadataOnly(r.Bundle); err != nil {
		return nil, err
	}
	switch r.Operation {
	case "observe":
		return e.ObserveContext(ctx, r.Bundle)
	case "stage":
		b, err := HydrateContent(ctx, e.root.Name(), r.Bundle, r.Operation, r.ContentSession)
		if err != nil {
			return nil, err
		}
		return e.EnsureContext(ctx, b, time.Now())
	case "confirm":
		return e.ConfirmContext(ctx, r.Bundle, r.Token, time.Now())
	default:
		return nil, fmt.Errorf("unsupported artifact operation")
	}
}

var supervisorAdmission = make(chan struct{}, 1)

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	select {
	case supervisorAdmission <- struct{}{}:
		defer func() { <-supervisorAdmission }()
	default:
		http.Error(w, "artifact admission full", http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/artifact" {
		http.Error(w, "unsupported request", http.StatusBadRequest)
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxMetadataBytes))
	if err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	var req Request
	if Decode(data, &req) != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	result, err := e.Execute(r.Context(), req)
	if err != nil {
		http.Error(w, "artifact operation rejected; inspect recovery phase", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
func SupervisorRequest(ctx context.Context, r Request) (*Result, error) {
	if err := MetadataOnly(r.Bundle); err != nil {
		return nil, err
	}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("encode artifact request")
	}
	if len(data) > MaxMetadataBytes {
		return nil, fmt.Errorf("artifact metadata too large")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", SocketPath)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 90 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://supervisor/artifact", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("external artifact supervisor unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("external artifact supervisor rejected operation")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read supervisor response")
	}
	var out Result
	if err := Decode(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
