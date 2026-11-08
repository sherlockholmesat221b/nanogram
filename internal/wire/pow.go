// File: internal/wire/pow.go

package wire

import "gitlab.com/sherlockholmesat221b/nanogram/internal/pow"

// PathPowChallenge is the unauthenticated endpoint that issues a challenge.
const PathPowChallenge = "/v1/pow/challenge"

// PowChallengeRequest asks for a challenge for one purpose and username.
type PowChallengeRequest struct {
	Purpose  string `json:"purpose"`
	Username string `json:"username"`
}

// PowChallengeResponse carries the challenge.
type PowChallengeResponse struct {
	Nonce      []byte `json:"nonce"`
	Difficulty uint8  `json:"difficulty"`
	IssuedAt   int64  `json:"issued_at"`
	MAC        []byte `json:"mac"`
}

// PowSolution is what the client sends back on the endpoint the challenge
// was for. It carries the challenge fields, so the server can verify the
// MAC without storing the challenge.
type PowSolution struct {
	Nonce           []byte `json:"nonce"`
	Difficulty      uint8  `json:"difficulty"`
	IssuedAt        int64  `json:"issued_at"`
	MAC             []byte `json:"mac"`
	SolutionCounter uint64 `json:"solution_counter"`
}

// ChallengeToWire converts a pow.Challenge to its wire form.
func ChallengeToWire(c pow.Challenge) PowChallengeResponse {
	return PowChallengeResponse{
		Nonce:      c.Nonce,
		Difficulty: c.Difficulty,
		IssuedAt:   c.IssuedAt,
		MAC:        c.MAC,
	}
}

// ChallengeFromWire converts a wire challenge to the pow type.
func ChallengeFromWire(w PowChallengeResponse) pow.Challenge {
	return pow.Challenge{
		Nonce:      w.Nonce,
		Difficulty: w.Difficulty,
		IssuedAt:   w.IssuedAt,
		MAC:        w.MAC,
	}
}

// SolutionToWire converts a pow.Solution to its wire form.
func SolutionToWire(s pow.Solution) PowSolution {
	return PowSolution{
		Nonce:           s.Nonce,
		Difficulty:      s.Difficulty,
		IssuedAt:        s.IssuedAt,
		MAC:             s.MAC,
		SolutionCounter: s.SolutionCounter,
	}
}

// SolutionFromWire converts a wire solution to the pow type.
func SolutionFromWire(w PowSolution) pow.Solution {
	return pow.Solution{
		Nonce:           w.Nonce,
		Difficulty:      w.Difficulty,
		IssuedAt:        w.IssuedAt,
		MAC:             w.MAC,
		SolutionCounter: w.SolutionCounter,
	}
}
