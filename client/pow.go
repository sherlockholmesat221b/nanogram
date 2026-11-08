// File: client/pow.go

package client

import (
	"fmt"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
)

// MaxPoWDifficulty is the highest difficulty this client will solve. A
// hostile server cannot make the client spend more than this per attempt.
// Two bits above the server's stated cap, for headroom.
const MaxPoWDifficulty = 22

// solveChallenge solves a challenge locally. It refuses a challenge above
// MaxPoWDifficulty, and it bounds the search to 32x the expected number of
// tries at that difficulty; if no solution is found within that, the
// challenge is treated as invalid rather than searched indefinitely.
func solveChallenge(c pow.Challenge) (pow.Solution, error) {
	if c.Difficulty > MaxPoWDifficulty {
		return pow.Solution{}, fmt.Errorf("%w: difficulty %d above client cap %d",
			ErrProtocol, c.Difficulty, MaxPoWDifficulty)
	}

	// Expected number of tries is 2^difficulty. 32x that gives essentially
	// certain success for a well-behaved hash; failure means the challenge
	// is broken.
	maxCounter := uint64(1) << (c.Difficulty + 5)

	counter, err := pow.Solve(c, maxCounter)
	if err != nil {
		return pow.Solution{}, fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	return pow.Solution{
		Nonce:           c.Nonce,
		Difficulty:      c.Difficulty,
		IssuedAt:        c.IssuedAt,
		MAC:             c.MAC,
		SolutionCounter: counter,
	}, nil
}
