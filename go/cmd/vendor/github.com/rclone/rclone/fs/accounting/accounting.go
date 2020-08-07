// Package accounting providers an accounting and limiting reader
package accounting

import (
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/rclone/rclone/fs/rc"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/asyncreader"
	"github.com/rclone/rclone/fs/fserrors"
)

// ErrorMaxTransferLimitReached defines error when transfer limit is reached.
// Used for checking on exit and matching to correct exit code.
var ErrorMaxTransferLimitReached = errors.New("Max transfer limit reached as set by --max-transfer")

// ErrorMaxTransferLimitReachedFatal is returned from Read when the max
// transfer limit is reached.
var ErrorMaxTransferLimitReachedFatal = fserrors.FatalError(ErrorMaxTransferLimitReached)

// Account limits and accounts for one transfer
type Account struct {
	stats *StatsInfo
	// The mutex is to make sure Read() and Close() aren't called
	// concurrently.  Unfortunately the persistent connection loop
	// in http transport calls Read() after Do() returns on
	// CancelRequest so this race can happen when it apparently
	// shouldn't.
	mu      sync.Mutex // mutex protects these values
	in      io.Reader
	origIn  io.ReadCloser
	close   io.Closer
	size    int64
	name    string
	closed  bool          // set if the file is closed
	exit    chan struct{} // channel that will be closed when transfer is finished
	withBuf bool          // is using a buffered in

	values accountValues
}

// accountValues holds statistics for this Account
type accountValues struct {
	mu      sync.Mutex // Mutex for stat values.
	bytes   int64      // Total number of bytes read
	max     int64      // if >=0 the max number of bytes to transfer
	start   time.Time  // Start time of first read
	lpTime  time.Time  // Time of last average measurement
	lpBytes int        // Number of bytes read since last measurement
	avg     float64    // Moving average of last few measurements in bytes/s
}

const averagePeriod = 16 // period to do exponentially weighted averages over

// newAccountSizeName makes an Account reader for an io.ReadCloser of
// the given size and name
func newAccountSizeName(stats *StatsInfo, in io.ReadCloser, size int64, name string) *Account {
	acc := &Account{
		stats:  stats,
		in:     in,
		close:  in,
		origIn: in,
		size:   size,
		name:   name,
		exit:   make(chan struct{}),
		values: accountValues{
			avg:    0,
			lpTime: time.Now(),
			max:    -1,
		},
	}
	if fs.Config.CutoffMode == fs.CutoffModeHard {
		acc.values.max = int64((fs.Config.MaxTransfer))
	}
	go acc.averageLoop()
	stats.inProgress.set(acc.name, acc)
	return acc
}

// WithBuffer - If the file is above a certain size it adds an Async reader
func (acc *Account) WithBuffer() *Account {
	// if already have a buffer then just return
	if acc.withBuf {
		return acc
	}
	acc.withBuf = true
	var buffers int
	if acc.size >= int64(fs.Config.BufferSize) || acc.size == -1 {
		buffers = int(int64(fs.Config.BufferSize) / asyncreader.BufferSize)
	} else {
		buffers = int(acc.size / asyncreader.BufferSize)
	}
	// On big files add a buffer
	if buffers > 0 {
		rc, err := asyncreader.New(acc.origIn, buffers)
		if err != nil {
			fs.Errorf(acc.name, "Failed to make buffer: %v", err)
		} else {
			acc.in = rc
			acc.close = rc
		}
	}
	return acc
}

// GetReader returns the underlying io.ReadCloser under any Buffer
func (acc *Account) GetReader() io.ReadCloser {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	return acc.origIn
}

// GetAsyncReader returns the current AsyncReader or nil if Account is unbuffered
func (acc *Account) GetAsyncReader() *asyncreader.AsyncReader {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	if asyncIn, ok := acc.in.(*asyncreader.AsyncReader); ok {
		return asyncIn
	}
	return nil
}

// StopBuffering stops the async buffer doing any more buffering
func (acc *Account) StopBuffering() {
	if asyncIn, ok := acc.in.(*asyncreader.AsyncReader); ok {
		asyncIn.Abandon()
	}
}

// UpdateReader updates the underlying io.ReadCloser stopping the
// async buffer (if any) and re-adding it
func (acc *Account) UpdateReader(in io.ReadCloser) {
	acc.mu.Lock()
	withBuf := acc.withBuf
	if withBuf {
		acc.StopBuffering()
		acc.withBuf = false
	}
	acc.in = in
	acc.close = in
	acc.origIn = in
	acc.closed = false
	if withBuf {
		acc.WithBuffer()
	}
	acc.mu.Unlock()

	// Reset counter to stop percentage going over 100%
	acc.values.mu.Lock()
	acc.values.lpBytes = 0
	acc.values.bytes = 0
	acc.values.mu.Unlock()
}

// averageLoop calculates averages for the stats in the background
func (acc *Account) averageLoop() {
	tick := time.NewTicker(time.Second)
	var period float64
	defer tick.Stop()
	for {
		select {
		case now := <-tick.C:
			acc.values.mu.Lock()
			// Add average of last second.
			elapsed := now.Sub(acc.values.lpTime).Seconds()
			avg := float64(acc.values.lpBytes) / elapsed
			// Soft start the moving average
			if period < averagePeriod {
				period++
			}
			acc.values.avg = (avg + (period-1)*acc.values.avg) / period
			acc.values.lpBytes = 0
			acc.values.lpTime = now
			// Unlock stats
			acc.values.mu.Unlock()
		case <-acc.exit:
			return
		}
	}
}

// Check the read before it has happened is valid returning the number
// of bytes remaining to read.
func (acc *Account) checkReadBefore() (bytesUntilLimit int64, err error) {
	acc.values.mu.Lock()
	if acc.values.max >= 0 {
		bytesUntilLimit = acc.values.max - acc.stats.GetBytes()
		if bytesUntilLimit < 0 {
			acc.values.mu.Unlock()
			return bytesUntilLimit, ErrorMaxTransferLimitReachedFatal
		}
	} else {
		bytesUntilLimit = 1 << 62
	}
	// Set start time.
	if acc.values.start.IsZero() {
		acc.values.start = time.Now()
	}
	acc.values.mu.Unlock()
	return bytesUntilLimit, nil
}

// Check the read call after the read has happened
func checkReadAfter(bytesUntilLimit int64, n int, err error) (outN int, outErr error) {
	bytesUntilLimit -= int64(n)
	if bytesUntilLimit < 0 {
		// chop the overage off
		n += int(bytesUntilLimit)
		if n < 0 {
			n = 0
		}
		err = ErrorMaxTransferLimitReachedFatal
	}
	return n, err
}

// ServerSideCopyStart should be called at the start of a server side copy
//
// This pretends a transfer has started
func (acc *Account) ServerSideCopyStart() {
	acc.values.mu.Lock()
	// Set start time.
	if acc.values.start.IsZero() {
		acc.values.start = time.Now()
	}
	acc.values.mu.Unlock()
}

// ServerSideCopyEnd accounts for a read of n bytes in a sever side copy
func (acc *Account) ServerSideCopyEnd(n int64) {
	// Update Stats
	acc.values.mu.Lock()
	acc.values.bytes += n
	acc.values.mu.Unlock()

	acc.stats.Bytes(n)
}

// Account the read and limit bandwidth
func (acc *Account) accountRead(n int) {
	// Update Stats
	acc.values.mu.Lock()
	acc.values.lpBytes += n
	acc.values.bytes += int64(n)
	acc.values.mu.Unlock()

	acc.stats.Bytes(int64(n))

	limitBandwidth(n)
}

// read bytes from the io.Reader passed in and account them
func (acc *Account) read(in io.Reader, p []byte) (n int, err error) {
	bytesUntilLimit, err := acc.checkReadBefore()
	if err == nil {
		n, err = in.Read(p)
		acc.accountRead(n)
		n, err = checkReadAfter(bytesUntilLimit, n, err)
	}
	return n, err
}

// Read bytes from the object - see io.Reader
func (acc *Account) Read(p []byte) (n int, err error) {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	return acc.read(acc.in, p)
}

// Thin wrapper for w
type accountWriteTo struct {
	w   io.Writer
	acc *Account
}

// Write writes len(p) bytes from p to the underlying data stream. It
// returns the number of bytes written from p (0 <= n <= len(p)) and
// any error encountered that caused the write to stop early. Write
// must return a non-nil error if it returns n < len(p). Write must
// not modify the slice data, even temporarily.
//
// Implementations must not retain p.
func (awt *accountWriteTo) Write(p []byte) (n int, err error) {
	bytesUntilLimit, err := awt.acc.checkReadBefore()
	if err == nil {
		n, err = awt.w.Write(p)
		n, err = checkReadAfter(bytesUntilLimit, n, err)
		awt.acc.accountRead(n)
	}
	return n, err
}

// WriteTo writes data to w until there's no more data to write or
// when an error occurs. The return value n is the number of bytes
// written. Any error encountered during the write is also returned.
func (acc *Account) WriteTo(w io.Writer) (n int64, err error) {
	acc.mu.Lock()
	in := acc.in
	acc.mu.Unlock()
	wrappedWriter := accountWriteTo{w: w, acc: acc}
	if do, ok := in.(io.WriterTo); ok {
		n, err = do.WriteTo(&wrappedWriter)
	} else {
		n, err = io.Copy(&wrappedWriter, in)
	}
	return
}

// AccountRead account having read n bytes
func (acc *Account) AccountRead(n int) (err error) {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	bytesUntilLimit, err := acc.checkReadBefore()
	if err == nil {
		n, err = checkReadAfter(bytesUntilLimit, n, err)
		acc.accountRead(n)
	}
	return err
}

// Close the object
func (acc *Account) Close() error {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	if acc.closed {
		return nil
	}
	acc.closed = true
	if acc.close == nil {
		return nil
	}
	return acc.close.Close()
}

// Done with accounting - must be called to free accounting goroutine
func (acc *Account) Done() {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	close(acc.exit)
	acc.stats.inProgress.clear(acc.name)
}

// progress returns bytes read as well as the size.
// Size can be <= 0 if the size is unknown.
func (acc *Account) progress() (bytes, size int64) {
	if acc == nil {
		return 0, 0
	}
	acc.values.mu.Lock()
	bytes, size = acc.values.bytes, acc.size
	acc.values.mu.Unlock()
	return bytes, size
}

// speed returns the speed of the current file transfer
// in bytes per second, as well an exponentially weighted moving average
// If no read has completed yet, 0 is returned for both values.
func (acc *Account) speed() (bps, current float64) {
	if acc == nil {
		return 0, 0
	}
	acc.values.mu.Lock()
	defer acc.values.mu.Unlock()
	if acc.values.bytes == 0 {
		return 0, 0
	}
	// Calculate speed from first read.
	total := float64(time.Now().Sub(acc.values.start)) / float64(time.Second)
	bps = float64(acc.values.bytes) / total
	current = acc.values.avg
	return
}

// eta returns the ETA of the current operation,
// rounded to full seconds.
// If the ETA cannot be determined 'ok' returns false.
func (acc *Account) eta() (etaDuration time.Duration, ok bool) {
	if acc == nil {
		return 0, false
	}
	acc.values.mu.Lock()
	defer acc.values.mu.Unlock()
	return eta(acc.values.bytes, acc.size, acc.values.avg)
}

// shortenName shortens in to size runes long
// If size <= 0 then in is left untouched
func shortenName(in string, size int) string {
	if size <= 0 {
		return in
	}
	if utf8.RuneCountInString(in) <= size {
		return in
	}
	name := []rune(in)
	size-- // don't count elipsis rune
	suffixLength := size / 2
	prefixLength := size - suffixLength
	suffixStart := len(name) - suffixLength
	name = append(append(name[:prefixLength], '…'), name[suffixStart:]...)
	return string(name)
}

// String produces stats for this file
func (acc *Account) String() string {
	a, b := acc.progress()
	_, cur := acc.speed()
	eta, etaok := acc.eta()
	etas := "-"
	if etaok {
		if eta > 0 {
			etas = fmt.Sprintf("%v", eta)
		} else {
			etas = "0s"
		}
	}

	if fs.Config.DataRateUnit == "bits" {
		cur = cur * 8
	}

	percentageDone := 0
	if b > 0 {
		percentageDone = int(100 * float64(a) / float64(b))
	}

	return fmt.Sprintf("%*s:%3d%% /%s, %s/s, %s",
		fs.Config.StatsFileNameLength,
		shortenName(acc.name, fs.Config.StatsFileNameLength),
		percentageDone,
		fs.SizeSuffix(b),
		fs.SizeSuffix(cur),
		etas,
	)
}

// RemoteStats produces stats for this file
func (acc *Account) RemoteStats() (out rc.Params) {
	out = make(rc.Params)
	a, b := acc.progress()
	out["bytes"] = a
	out["size"] = b
	spd, cur := acc.speed()
	out["speed"] = spd
	out["speedAvg"] = cur

	eta, etaok := acc.eta()
	out["eta"] = nil
	if etaok {
		if eta > 0 {
			out["eta"] = eta.Seconds()
		} else {
			out["eta"] = 0
		}
	}
	out["name"] = acc.name

	percentageDone := 0
	if b > 0 {
		percentageDone = int(100 * float64(a) / float64(b))
	}
	out["percentage"] = percentageDone
	out["group"] = acc.stats.group

	return out
}

// OldStream returns the top io.Reader
func (acc *Account) OldStream() io.Reader {
	acc.mu.Lock()
	defer acc.mu.Unlock()
	return acc.in
}

// SetStream updates the top io.Reader
func (acc *Account) SetStream(in io.Reader) {
	acc.mu.Lock()
	acc.in = in
	acc.mu.Unlock()
}

// WrapStream wraps an io Reader so it will be accounted in the same
// way as account
func (acc *Account) WrapStream(in io.Reader) io.Reader {
	return &accountStream{
		acc: acc,
		in:  in,
	}
}

// accountStream accounts a single io.Reader into a parent *Account
type accountStream struct {
	acc *Account
	in  io.Reader
}

// OldStream return the underlying stream
func (a *accountStream) OldStream() io.Reader {
	return a.in
}

// SetStream set the underlying stream
func (a *accountStream) SetStream(in io.Reader) {
	a.in = in
}

// WrapStream wrap in in an accounter
func (a *accountStream) WrapStream(in io.Reader) io.Reader {
	return a.acc.WrapStream(in)
}

// Read bytes from the object - see io.Reader
func (a *accountStream) Read(p []byte) (n int, err error) {
	return a.acc.read(a.in, p)
}

// Accounter accounts a stream allowing the accounting to be removed and re-added
type Accounter interface {
	io.Reader
	OldStream() io.Reader
	SetStream(io.Reader)
	WrapStream(io.Reader) io.Reader
}

// WrapFn wraps an io.Reader (for accounting purposes usually)
type WrapFn func(io.Reader) io.Reader

// UnWrap unwraps a reader returning unwrapped and wrap, a function to
// wrap it back up again.  If `in` is an Accounter then this function
// will take the accounting unwrapped and wrap will put it back on
// again the new Reader passed in.
//
// This allows functions which wrap io.Readers to move the accounting
// to the end of the wrapped chain of readers.  This is very important
// if buffering is being introduced and if the Reader might be wrapped
// again.
func UnWrap(in io.Reader) (unwrapped io.Reader, wrap WrapFn) {
	acc, ok := in.(Accounter)
	if !ok {
		return in, func(r io.Reader) io.Reader { return r }
	}
	return acc.OldStream(), acc.WrapStream
}
