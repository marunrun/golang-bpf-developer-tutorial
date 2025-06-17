package utils

import (
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// ShutdownListen 监听关闭信号并阻塞直到收到信号
func ShutdownListen() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	println("Press Ctrl+C to stop...")
	<-sig
	println("Received shutdown signal, exiting...")
}

// ShutdownListenWithCallback 监听关闭信号并执行清理回调函数
func ShutdownListenWithCallback(cleanup func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	println("Press Ctrl+C to stop...")
	<-sig
	println("Received shutdown signal, cleaning up...")

	if cleanup != nil {
		cleanup()
	}

	println("Cleanup completed, exiting...")
}

// ShutdownListenWithTimeout 监听关闭信号，支持超时强制退出
func ShutdownListenWithTimeout(timeout time.Duration, cleanup func()) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	println("Press Ctrl+C to stop...")
	<-sig
	println("Received shutdown signal, cleaning up...")

	if cleanup != nil {
		// 创建带超时的 context
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		done := make(chan struct{})
		go func() {
			defer close(done)
			cleanup()
		}()

		select {
		case <-done:
			println("Cleanup completed successfully")
		case <-ctx.Done():
			println("Cleanup timeout, forcing exit...")
		}
	}

	println("Exiting...")
}

// ShutdownListenWithContext 返回一个可以取消的 context
func ShutdownListenWithContext(ctx context.Context) context.Context {
	ctx, cancel := context.WithCancel(ctx)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		defer cancel()
		println("Press Ctrl+C to stop...")

		select {
		case <-sig:
			println("Received shutdown signal, canceling context...")
		case <-ctx.Done():
			// Context 已经被其他地方取消
		}
	}()

	return ctx
}
