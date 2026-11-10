// Package passwd reads the password without echo (or from stdin for scripts).
package passwd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Read returns the password. With fromStdin it reads one line from stdin;
// otherwise it prompts on the terminal without echo. The password is never
// taken from arguments or the environment (history / process-list leaks).
func Read(prompt string, fromStdin bool) ([]byte, error) {
	if fromStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return nil, err
		}
		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal: use --password-stdin")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return b, err
}
