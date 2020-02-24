package helper

import (
	"fmt"
	"os"
)

// PrintError prints message to Stderr
func PrintError(a ...interface{}) {
	fmt.Fprintln(os.Stderr, a...)
}
