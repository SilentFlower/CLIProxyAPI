// Package auth 提供认证管理和调度功能。
// 本文件实现了 per-auth 请求节流器和并发控制器，
// 用于模拟人类操作节奏，防止账号因异常请求模式被检测。
package auth

import (
	"context"
	"sync"
	"time"
)

// authThrottler 控制每个上游账号的请求频率和并发数。
// 通过最小请求间隔、RPM 滑动窗口和并发信号量三个维度进行限制。
//
// 线程安全：所有操作通过互斥锁保护，可被多个 goroutine 并发调用。
type authThrottler struct {
	mu          sync.Mutex
	lastRequest map[string]time.Time   // authID -> 最后一次请求的时间戳
	rpmWindows  map[string][]time.Time // authID -> 滑动窗口内的请求时间戳列表

	semMu      sync.Mutex
	semaphores map[string]chan struct{} // authID -> 并发控制信号量

	minInterval time.Duration // 最小请求间隔
	maxRPM      int           // 每分钟最大请求数（0 = 不限制）
	maxConc     int           // 最大并发数（0 = 不限制）
}

// newAuthThrottler 创建一个新的请求节流器。
// 所有参数为 0 时表示不启用任何限制。
//
// 参数：
//   - minIntervalMs: 最小请求间隔（毫秒），0 = 不限制
//   - maxRPM: 每分钟最大请求数，0 = 不限制
//   - maxConcurrency: 最大并发数，0 = 不限制
func newAuthThrottler(minIntervalMs, maxRPM, maxConcurrency int) *authThrottler {
	var minInterval time.Duration
	if minIntervalMs > 0 {
		minInterval = time.Duration(minIntervalMs) * time.Millisecond
	}
	return &authThrottler{
		lastRequest: make(map[string]time.Time),
		rpmWindows:  make(map[string][]time.Time),
		semaphores:  make(map[string]chan struct{}),
		minInterval: minInterval,
		maxRPM:      maxRPM,
		maxConc:     maxConcurrency,
	}
}

// Enabled 返回节流器是否启用了任何限制。
func (t *authThrottler) Enabled() bool {
	return t.minInterval > 0 || t.maxRPM > 0
}

// ConcurrencyEnabled 返回是否启用了并发控制。
func (t *authThrottler) ConcurrencyEnabled() bool {
	return t.maxConc > 0
}

// Acquire 检查指定账号的请求频率限制，返回需要等待的时间。
// 如果无需等待则返回 0。调用此方法会记录一次请求。
//
// 参数：
//   - authID: 上游账号标识
//
// 返回值：
//   - wait: 需要等待的时间（0 表示立即可用）
func (t *authThrottler) Acquire(authID string) time.Duration {
	if !t.Enabled() {
		return 0
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	var wait time.Duration

	// 检查最小请求间隔
	if t.minInterval > 0 {
		if last, ok := t.lastRequest[authID]; ok {
			elapsed := now.Sub(last)
			if elapsed < t.minInterval {
				wait = t.minInterval - elapsed
			}
		}
	}

	// 检查 RPM 滑动窗口
	if t.maxRPM > 0 {
		windowStart := now.Add(-time.Minute)
		// 清理窗口外的过期时间戳
		window := t.rpmWindows[authID]
		validStart := 0
		for validStart < len(window) && window[validStart].Before(windowStart) {
			validStart++
		}
		if validStart > 0 {
			window = window[validStart:]
		}
		t.rpmWindows[authID] = window

		if len(window) >= t.maxRPM {
			// 等待最早的请求过期出窗口
			rpmWait := window[0].Add(time.Minute).Sub(now)
			if rpmWait > wait {
				wait = rpmWait
			}
		}
	}

	// 记录请求时间（使用 now + wait 作为实际请求时间）
	requestTime := now.Add(wait)
	t.lastRequest[authID] = requestTime
	if t.maxRPM > 0 {
		t.rpmWindows[authID] = append(t.rpmWindows[authID], requestTime)
	}

	return wait
}

// AcquireConcurrency 获取指定账号的并发请求槽位。
// 如果并发槽已满，会阻塞等待直到有可用槽位或 context 取消。
//
// 返回值：
//   - release: 释放函数，调用者必须在请求完成后调用以归还槽位
//   - err: 仅当 context 取消时返回错误
func (t *authThrottler) AcquireConcurrency(ctx context.Context, authID string) (release func(), err error) {
	if !t.ConcurrencyEnabled() {
		return func() {}, nil
	}

	sem := t.getOrCreateSemaphore(authID)

	select {
	case sem <- struct{}{}:
		return func() { <-sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// getOrCreateSemaphore 获取或创建指定账号的并发信号量。
func (t *authThrottler) getOrCreateSemaphore(authID string) chan struct{} {
	t.semMu.Lock()
	defer t.semMu.Unlock()

	if sem, ok := t.semaphores[authID]; ok {
		return sem
	}
	sem := make(chan struct{}, t.maxConc)
	t.semaphores[authID] = sem
	return sem
}

// UpdateConfig 更新节流器的配置参数。
// 线程安全，可在运行时调用以响应配置热重载。
func (t *authThrottler) UpdateConfig(minIntervalMs, maxRPM, maxConcurrency int) {
	t.mu.Lock()
	if minIntervalMs > 0 {
		t.minInterval = time.Duration(minIntervalMs) * time.Millisecond
	} else {
		t.minInterval = 0
	}
	t.maxRPM = maxRPM
	t.mu.Unlock()

	// 并发数变化需要重建信号量
	t.semMu.Lock()
	if maxConcurrency != t.maxConc {
		t.maxConc = maxConcurrency
		// 重建所有信号量（已有的 goroutine 持有的旧信号量会自然释放）
		t.semaphores = make(map[string]chan struct{})
	}
	t.semMu.Unlock()
}
