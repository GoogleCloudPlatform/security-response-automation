//go:generate go run generator.go

package storage

// FileStore is embedded storage to save time reading Rego from disk
var FileStore = newEmbeddedStorage()

type embededStorage map[string][]byte

func newEmbeddedStorage() embededStorage {
	return make(map[string][]byte)
}

// Add a file to box
func (e embededStorage) Add(file string, content []byte) {
	e[file] = content
}
