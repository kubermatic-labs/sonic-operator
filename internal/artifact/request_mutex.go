// SPDX-License-Identifier: Apache-2.0
package artifact

import (
	"context"
	"sync"
)

type requestMutex struct {
	once sync.Once
	slot chan struct{}
}

func (m *requestMutex) init() {
	m.once.Do(func() { m.slot = make(chan struct{}, 1); m.slot <- struct{}{} })
}
func (m *requestMutex) Lock() { _ = m.LockContext(context.Background()) }
func (m *requestMutex) LockContext(ctx context.Context) error {
	m.init()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-m.slot:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	}
}
func (m *requestMutex) Unlock() { m.slot <- struct{}{} }
func (e *Engine) bindRequest(ctx context.Context) func() {
	e.requestContext = ctx
	return func() { e.requestContext = nil }
}
func (e *Engine) boundContext(ctx context.Context) (context.Context, func()) {
	if e.requestContext == nil {
		return ctx, func() {}
	}
	child, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(e.requestContext, cancel)
	if e.requestContext.Err() != nil {
		cancel()
	}
	return child, func() { stop(); cancel() }
}
