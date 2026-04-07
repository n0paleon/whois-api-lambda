package workerpool

import (
	"sync"

	"github.com/panjf2000/ants/v2"
)

var (
	p    *ants.Pool
	once sync.Once
)

func init() {
	once.Do(func() {
		pool, _ := ants.NewPool(500, ants.WithPreAlloc(true))
		p = pool
	})
}

func Submit(fn func()) error {
	return p.Submit(fn)
}
