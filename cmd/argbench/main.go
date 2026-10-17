package main

import (
	"fmt"
	"sort"
	"time"

	"golang.org/x/crypto/argon2"
)

func bench(memMiB, passes uint32) time.Duration {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")

	memKiB := memMiB * 1024

	argon2.IDKey(password, salt, passes, memKiB, 1, 32)

	runs := make([]time.Duration, 3)
	for i := range runs {
		start := time.Now()
		argon2.IDKey(password, salt, passes, memKiB, 1, 32)
		runs[i] = time.Since(start)
	}

	sort.Slice(runs, func(i, j int) bool {
		return runs[i] < runs[j]
	})

	return runs[1]
}

func main() {
	for _, memMiB := range []uint32{32, 64, 128} {
		for _, passes := range []uint32{1, 3} {
			median := bench(memMiB, passes)
			fmt.Printf("mem=%dMiB passes=%d median=%dms\n",
				memMiB, passes, median.Milliseconds())
		}
	}
}
