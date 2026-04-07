package ports

type WorkerPool interface {
	Submit(task func()) error
}