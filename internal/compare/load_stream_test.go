//go:build !windows

package compare

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestLoadStopsReadingAnEndlessStream is the reason the cap exists: a stream
// that never ends, such as /dev/zero or a pipe from a runaway producer, must
// fail as soon as it passes the cap instead of growing the process until the
// runtime aborts. The stream is a pipe addressed through /dev/fd/N, the path a
// shell's process substitution hands out, so a non-regular input is read the
// same way a file is. Descriptor paths are a Unix concept, hence the build tag.
func TestLoadStopsReadingAnEndlessStream(t *testing.T) {
	oldLimit := MaxReportBytes
	t.Cleanup(func() { MaxReportBytes = oldLimit })
	MaxReportBytes = 1 << 20

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer writer.Close()
		chunk := bytes.Repeat([]byte{0}, 64<<10)
		for {
			// The write fails once the reader is closed, which ends the
			// producer.
			if _, err := writer.Write(chunk); err != nil {
				return
			}
		}
	}()

	path := fmt.Sprintf("/dev/fd/%d", reader.Fd())
	_, err = Load(path)
	if closeErr := reader.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	<-stopped
	if err == nil || !strings.Contains(err.Error(), "1 MiB limit") {
		t.Fatalf("Load(endless stream) = %v, want the size limit error", err)
	}
}

// TestLoadJoinsAStreamLongerThanOneChunk pins the other side of the cap for
// inputs without a size: a stream within the cap but longer than one read
// buffer arrives in several chunks, and they must be joined back into the
// exact report rather than truncated to the first one.
func TestLoadJoinsAStreamLongerThanOneChunk(t *testing.T) {
	document, err := os.ReadFile(writeReportFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	// JSON permits trailing whitespace, so padding lengthens the stream and
	// changes nothing else.
	document = append(document, bytes.Repeat([]byte(" "), 2*reportReadChunk)...)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	written := make(chan error, 1)
	go func() {
		_, writeErr := writer.Write(document)
		if closeErr := writer.Close(); writeErr == nil {
			writeErr = closeErr
		}
		written <- writeErr
	}()

	content, err := readReportInput(fmt.Sprintf("/dev/fd/%d", reader.Fd()))
	if err != nil || !bytes.Equal(content, document) {
		t.Fatalf("readReportInput(long stream) = %d bytes/%v, want %d bytes", len(content), err, len(document))
	}
	if err := <-written; err != nil {
		t.Fatalf("pipe producer: %v", err)
	}
}
