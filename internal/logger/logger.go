package logger

import "log"

var verbose = false

func EnableVerbose() {
	verbose = true
}
func Log(message string) {
	if verbose {
		log.Println(message)
	}
}
