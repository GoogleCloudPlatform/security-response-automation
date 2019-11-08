package mode

import "os"

// OFF if the operation mode of the CF is OFF
func OFF() bool {
	return os.Getenv("MODE") == "OFF"
}

// DryRun if the operation mode of the CF is DRY-RUN
func DryRun() bool {
	return os.Getenv("MODE") == "DRY-RUN"
}
