// File: client/username.go

package client

import "regexp"

// usernamePattern must stay the same as the pattern the service uses. An
// end-to-end test checks that the two agree.
var usernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.]{3,32}$`)

// ValidUsername reports whether the server accepts the format of a username:
// 3 to 32 characters from a-z, A-Z, 0-9, underscore and dot. Checking it first
// means a bad name is found before a passphrase is made.
func ValidUsername(username string) bool {
	return usernamePattern.MatchString(username)
}
