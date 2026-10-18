// File: cmd/argwasm/main.go

package main

import (
	"fmt"
	"math"
	"sort"
	"syscall/js"
	"time"

	"golang.org/x/crypto/argon2"
)

func bench(memMiB, passes, timedRuns uint32) (time.Duration, time.Duration) {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	memKiB := memMiB * 1024

	argon2.IDKey(password, salt, passes, memKiB, 1, 32)

	runs := make([]time.Duration, timedRuns)
	for i := range runs {
		start := time.Now()
		argon2.IDKey(password, salt, passes, memKiB, 1, 32)
		runs[i] = time.Since(start)
	}

	sort.Slice(runs, func(i, j int) bool {
		return runs[i] < runs[j]
	})

	return runs[0], runs[len(runs)/2]
}

func runBench(this js.Value, args []js.Value) (result any) {
	js.Global().Set("lastBenchError", "")

	defer func() {
		if r := recover(); r != nil {
			js.Global().Set("lastBenchError", fmt.Sprint(r))
			result = math.NaN()
		}
	}()

	if len(args) != 3 {
		panic("runBench requires memMiB, passes, and timedRuns")
	}

	mem, passes, timedRuns := args[0].Int(), args[1].Int(), args[2].Int()
	if mem <= 0 || passes <= 0 || timedRuns <= 0 {
		panic("memMiB, passes, and timedRuns must be positive integers")
	}

	min, median := bench(uint32(mem), uint32(passes), uint32(timedRuns))

	return map[string]any{
		"min":    min.Milliseconds(),
		"median": median.Milliseconds(),
	}
}

func main() {
	js.Global().Set("runBench", js.FuncOf(runBench))
	select {}
}
