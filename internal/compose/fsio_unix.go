//go:build unix

package compose

import "os"

// fsyncDir fsyncs a directory so a rename/create within it is durable — on a
// crash an unsynced entry can leave a durable file with no findable name.
func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
