package utils

import (
	"os"
)

func EnsureStaticFolder() error {
	_, err := os.Stat("./static")
	if os.IsNotExist(err) {
		err := os.Mkdir("./static", 0755)
		if err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return nil
}
