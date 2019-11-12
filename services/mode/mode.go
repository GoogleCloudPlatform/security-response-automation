package mode

import "os"

// DryRun if the operation mode of the CF is DRY-RUN
func DryRun() bool {
	return os.Getenv("MODE") == "DRY-RUN"
}
