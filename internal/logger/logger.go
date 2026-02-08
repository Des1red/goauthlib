package logger

import (
	"fmt"
	"log"
)

var verbose = false

func EnableVerbose() {
	verbose = true
}
func Log(message string) {
	if verbose {
		log.Println(message)
	}
}

func Newline() {
	if verbose {
		fmt.Println()
	}
}
