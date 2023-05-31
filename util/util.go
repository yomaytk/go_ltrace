package util

import "log"

func ErrFatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
