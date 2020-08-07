// Package cmd implemnts the rclone command
//
// It is in a sub package so it's internals can be re-used elsewhere
package cmd

// FIXME only attach the remote flags when using a remote???
// would probably mean bringing all the flags in to here? Or define some flagsets in fs...

import (
	"fmt"
	"log"
	"math/rand"
	"os"
	"os/exec"
	"path"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
	"github.com/rclone/rclone/fs/cache"
	"github.com/rclone/rclone/fs/config/configflags"
	"github.com/rclone/rclone/fs/config/flags"
	"github.com/rclone/rclone/fs/filter"
	"github.com/rclone/rclone/fs/filter/filterflags"
	"github.com/rclone/rclone/fs/fserrors"
	"github.com/rclone/rclone/fs/fspath"
	fslog "github.com/rclone/rclone/fs/log"
	"github.com/rclone/rclone/fs/rc/rcflags"
	"github.com/rclone/rclone/fs/rc/rcserver"
	"github.com/rclone/rclone/lib/atexit"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Globals
var (
	// Flags
	cpuProfile      = flags.StringP("cpuprofile", "", "", "Write cpu profile to file")
	memProfile      = flags.StringP("memprofile", "", "", "Write memory profile to file")
	statsInterval   = flags.DurationP("stats", "", time.Minute*1, "Interval between printing stats, e.g 500ms, 60s, 5m. (0 to disable)")
	dataRateUnit    = flags.StringP("stats-unit", "", "bytes", "Show data rate in stats as either 'bits' or 'bytes'/s")
	version         bool
	retries         = flags.IntP("retries", "", 3, "Retry operations this many times if they fail")
	retriesInterval = flags.DurationP("retries-sleep", "", 0, "Interval between retrying operations if they fail, e.g 500ms, 60s, 5m. (0 to disable)")
	// Errors
	errorCommandNotFound    = errors.New("command not found")
	errorUncategorized      = errors.New("uncategorized error")
	errorNotEnoughArguments = errors.New("not enough arguments")
	errorTooManyArguments   = errors.New("too many arguments")
)

const (
	exitCodeSuccess = iota
	exitCodeUsageError
	exitCodeUncategorizedError
	exitCodeDirNotFound
	exitCodeFileNotFound
	exitCodeRetryError
	exitCodeNoRetryError
	exitCodeFatalError
	exitCodeTransferExceeded
	exitCodeNoFilesTransferred
)

// ShowVersion prints the version to stdout
func ShowVersion() {
	fmt.Printf("rclone %s\n", fs.Version)
	fmt.Printf("- os/arch: %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("- go version: %s\n", runtime.Version())
}

// NewFsFile creates an Fs from a name but may point to a file.
//
// It returns a string with the file name if points to a file
// otherwise "".
func NewFsFile(remote string) (fs.Fs, string) {
	_, _, fsPath, err := fs.ParseRemote(remote)
	if err != nil {
		err = fs.CountError(err)
		log.Fatalf("Failed to create file system for %q: %v", remote, err)
	}
	f, err := cache.Get(remote)
	switch err {
	case fs.ErrorIsFile:
		return f, path.Base(fsPath)
	case nil:
		return f, ""
	default:
		err = fs.CountError(err)
		log.Fatalf("Failed to create file system for %q: %v", remote, err)
	}
	return nil, ""
}

// newFsFileAddFilter creates an src Fs from a name
//
// This works the same as NewFsFile however it adds filters to the Fs
// to limit it to a single file if the remote pointed to a file.
func newFsFileAddFilter(remote string) (fs.Fs, string) {
	f, fileName := NewFsFile(remote)
	if fileName != "" {
		if !filter.Active.InActive() {
			err := errors.Errorf("Can't limit to single files when using filters: %v", remote)
			err = fs.CountError(err)
			//zyb log.Fatalf(err.Error())
		}
		// Limit transfers to this file
		err := filter.Active.AddFile(fileName)
		if err != nil {
			err = fs.CountError(err)
			//zyb log.Fatalf("Failed to limit to single file %q: %v", remote, err)
		}
	}
	return f, fileName
}

// NewFsSrc creates a new src fs from the arguments.
//
// The source can be a file or a directory - if a file then it will
// limit the Fs to a single file.
func NewFsSrc(args []string) fs.Fs {
	fsrc, _ := newFsFileAddFilter(args[0])
	return fsrc
}

// newFsDir creates an Fs from a name
//
// This must point to a directory
func newFsDir(remote string) fs.Fs {
	f, err := cache.Get(remote)
	if err != nil {
		err = fs.CountError(err)
		log.Fatalf("Failed to create file system for %q: %v", remote, err)
	}
	return f
}

// NewFsDir creates a new Fs from the arguments
//
// The argument must point a directory
func NewFsDir(args []string) fs.Fs {
	fdst := newFsDir(args[0])
	return fdst
}

// NewFsSrcDst creates a new src and dst fs from the arguments
func NewFsSrcDst(args []string) (fs.Fs, fs.Fs) {
	fsrc, _ := newFsFileAddFilter(args[0])
	fdst := newFsDir(args[1])
	return fsrc, fdst
}

// NewFsSrcFileDst creates a new src and dst fs from the arguments
//
// The source may be a file, in which case the source Fs and file name is returned
func NewFsSrcFileDst(args []string) (fsrc fs.Fs, srcFileName string, fdst fs.Fs) {
	fsrc, srcFileName = NewFsFile(args[0])
	fdst = newFsDir(args[1])
	return fsrc, srcFileName, fdst
}

// NewFsSrcDstFiles creates a new src and dst fs from the arguments
// If src is a file then srcFileName and dstFileName will be non-empty
func NewFsSrcDstFiles(args []string) (fsrc fs.Fs, srcFileName string, fdst fs.Fs, dstFileName string) {
	fsrc, srcFileName = newFsFileAddFilter(args[0])
	// If copying a file...
	dstRemote := args[1]
	// If file exists then srcFileName != "", however if the file
	// doesn't exist then we assume it is a directory...
	if srcFileName != "" {
		var err error
		dstRemote, dstFileName, err = fspath.Split(dstRemote)
		if err != nil {
			log.Fatalf("Parsing %q failed: %v", args[1], err)
		}
		if dstRemote == "" {
			dstRemote = "."
		}
		if dstFileName == "" {
			log.Fatalf("%q is a directory", args[1])
		}
	}
	fdst, err := cache.Get(dstRemote)
	switch err {
	case fs.ErrorIsFile:
		_ = fs.CountError(err)
		log.Fatalf("Source doesn't exist or is a directory and destination is a file")
	case nil:
	default:
		_ = fs.CountError(err)
		log.Fatalf("Failed to create file system for destination %q: %v", dstRemote, err)
	}
	return
}

// NewFsDstFile creates a new dst fs with a destination file name from the arguments
func NewFsDstFile(args []string) (fdst fs.Fs, dstFileName string) {
	dstRemote, dstFileName, err := fspath.Split(args[0])
	if err != nil {
		log.Fatalf("Parsing %q failed: %v", args[0], err)
	}
	if dstRemote == "" {
		dstRemote = "."
	}
	if dstFileName == "" {
		log.Fatalf("%q is a directory", args[0])
	}
	fdst = newFsDir(dstRemote)
	return
}

// ShowStats returns true if the user added a `--stats` flag to the command line.
//
// This is called by Run to override the default value of the
// showStats passed in.
func ShowStats() bool {
	statsIntervalFlag := pflag.Lookup("stats")
	return statsIntervalFlag != nil && statsIntervalFlag.Changed
}

// Run the function with stats and retries if required
func Run(Retry bool, showStats bool, cmd *cobra.Command, f func() error) {
	var cmdErr error
	stopStats := func() {}
	if !showStats && ShowStats() {
		showStats = true
	}
	if fs.Config.Progress {
		stopStats = startProgress()
	} else if showStats {
		stopStats = StartStats()
	}
	SigInfoHandler()
	for try := 1; try <= *retries; try++ {
		cmdErr = f()
		cmdErr = fs.CountError(cmdErr)
		lastErr := accounting.GlobalStats().GetLastError()
		if cmdErr == nil {
			cmdErr = lastErr
		}
		if !Retry || !accounting.GlobalStats().Errored() {
			if try > 1 {
				fs.Errorf(nil, "Attempt %d/%d succeeded", try, *retries)
			}
			break
		}
		if accounting.GlobalStats().HadFatalError() {
			fs.Errorf(nil, "Fatal error received - not attempting retries")
			break
		}
		if accounting.GlobalStats().Errored() && !accounting.GlobalStats().HadRetryError() {
			fs.Errorf(nil, "Can't retry this error - not attempting retries")
			break
		}
		if retryAfter := accounting.GlobalStats().RetryAfter(); !retryAfter.IsZero() {
			d := retryAfter.Sub(time.Now())
			if d > 0 {
				fs.Logf(nil, "Received retry after error - sleeping until %s (%v)", retryAfter.Format(time.RFC3339Nano), d)
				time.Sleep(d)
			}
		}
		if lastErr != nil {
			fs.Errorf(nil, "Attempt %d/%d failed with %d errors and: %v", try, *retries, accounting.GlobalStats().GetErrors(), lastErr)
		} else {
			fs.Errorf(nil, "Attempt %d/%d failed with %d errors", try, *retries, accounting.GlobalStats().GetErrors())
		}
		if try < *retries {
			accounting.GlobalStats().ResetErrors()
		}
		if *retriesInterval > 0 {
			time.Sleep(*retriesInterval)
		}
	}
	stopStats()
	if showStats && (accounting.GlobalStats().Errored() || *statsInterval > 0) {
		accounting.GlobalStats().Log()
	}
	fs.Debugf(nil, "%d go routines active\n", runtime.NumGoroutine())

	// dump all running go-routines
	if fs.Config.Dump&fs.DumpGoRoutines != 0 {
		err := pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		if err != nil {
			fs.Errorf(nil, "Failed to dump goroutines: %v", err)
		}
	}

	// dump open files
	if fs.Config.Dump&fs.DumpOpenFiles != 0 {
		c := exec.Command("lsof", "-p", strconv.Itoa(os.Getpid()))
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		err := c.Run()
		if err != nil {
			fs.Errorf(nil, "Failed to list open files: %v", err)
		}
	}

	// Log the final error message and exit
	if cmdErr != nil {
		nerrs := accounting.GlobalStats().GetErrors()
		if nerrs <= 1 {
			log.Printf("Failed to %s: %v", cmd.Name(), cmdErr)
		} else {
			log.Printf("Failed to %s with %d errors: last error was: %v", cmd.Name(), nerrs, cmdErr)
		}
	}
	resolveExitCode(cmdErr)

}

// CheckArgs checks there are enough arguments and prints a message if not
func CheckArgs(MinArgs, MaxArgs int, cmd *cobra.Command, args []string) {
	if len(args) < MinArgs {
		_ = cmd.Usage()
		_, _ = fmt.Fprintf(os.Stderr, "Command %s needs %d arguments minimum: you provided %d non flag arguments: %q\n", cmd.Name(), MinArgs, len(args), args)
		resolveExitCode(errorNotEnoughArguments)
	} else if len(args) > MaxArgs {
		_ = cmd.Usage()
		_, _ = fmt.Fprintf(os.Stderr, "Command %s needs %d arguments maximum: you provided %d non flag arguments: %q\n", cmd.Name(), MaxArgs, len(args), args)
		resolveExitCode(errorTooManyArguments)
	}
}

// StartStats prints the stats every statsInterval
//
// It returns a func which should be called to stop the stats.
func StartStats() func() {
	if *statsInterval <= 0 {
		return func() {}
	}
	stopStats := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(*statsInterval)
		for {
			select {
			case <-ticker.C:
				accounting.GlobalStats().Log()
			case <-stopStats:
				ticker.Stop()
				return
			}
		}
	}()
	return func() {
		close(stopStats)
		wg.Wait()
	}
}

// initConfig is run by cobra after initialising the flags
func initConfig() {
	// Start the logger
	fslog.InitLogging()

	// Finish parsing any command line flags
	configflags.SetFlags()

	// Load filters
	err := filterflags.Reload()
	if err != nil {
		log.Fatalf("Failed to load filters: %v", err)
	}

	// Write the args for debug purposes
	fs.Debugf("rclone", "Version %q starting with parameters %q", fs.Version, os.Args)

	// Start the remote control server if configured
	_, err = rcserver.Start(&rcflags.Opt)
	if err != nil {
		log.Fatalf("Failed to start remote control: %v", err)
	}

	// Setup CPU profiling if desired
	if *cpuProfile != "" {
		fs.Infof(nil, "Creating CPU profile %q\n", *cpuProfile)
		f, err := os.Create(*cpuProfile)
		if err != nil {
			err = fs.CountError(err)
			log.Fatal(err)
		}
		err = pprof.StartCPUProfile(f)
		if err != nil {
			err = fs.CountError(err)
			log.Fatal(err)
		}
		atexit.Register(func() {
			pprof.StopCPUProfile()
		})
	}

	// Setup memory profiling if desired
	if *memProfile != "" {
		atexit.Register(func() {
			fs.Infof(nil, "Saving Memory profile %q\n", *memProfile)
			f, err := os.Create(*memProfile)
			if err != nil {
				err = fs.CountError(err)
				log.Fatal(err)
			}
			err = pprof.WriteHeapProfile(f)
			if err != nil {
				err = fs.CountError(err)
				log.Fatal(err)
			}
			err = f.Close()
			if err != nil {
				err = fs.CountError(err)
				log.Fatal(err)
			}
		})
	}

	if m, _ := regexp.MatchString("^(bits|bytes)$", *dataRateUnit); m == false {
		fs.Errorf(nil, "Invalid unit passed to --stats-unit. Defaulting to bytes.")
		fs.Config.DataRateUnit = "bytes"
	} else {
		fs.Config.DataRateUnit = *dataRateUnit
	}
}

func resolveExitCode(err error) {
	atexit.Run()
	if err == nil {
		if fs.Config.ErrorOnNoTransfer {
			if accounting.GlobalStats().GetTransfers() == 0 {
				os.Exit(exitCodeNoFilesTransferred)
			}
		}
		os.Exit(exitCodeSuccess)
	}

	_, unwrapped := fserrors.Cause(err)

	switch {
	case unwrapped == fs.ErrorDirNotFound:
		os.Exit(exitCodeDirNotFound)
	case unwrapped == fs.ErrorObjectNotFound:
		os.Exit(exitCodeFileNotFound)
	case unwrapped == errorUncategorized:
		os.Exit(exitCodeUncategorizedError)
	case unwrapped == accounting.ErrorMaxTransferLimitReached:
		os.Exit(exitCodeTransferExceeded)
	case fserrors.ShouldRetry(err):
		os.Exit(exitCodeRetryError)
	case fserrors.IsNoRetryError(err):
		os.Exit(exitCodeNoRetryError)
	case fserrors.IsFatalError(err):
		os.Exit(exitCodeFatalError)
	default:
		os.Exit(exitCodeUsageError)
	}
}

var backendFlags map[string]struct{}

// AddBackendFlags creates flags for all the backend options
func AddBackendFlags() {
	backendFlags = map[string]struct{}{}
	for _, fsInfo := range fs.Registry {
		done := map[string]struct{}{}
		for i := range fsInfo.Options {
			opt := &fsInfo.Options[i]
			// Skip if done already (eg with Provider options)
			if _, doneAlready := done[opt.Name]; doneAlready {
				continue
			}
			done[opt.Name] = struct{}{}
			// Make a flag from each option
			name := opt.FlagName(fsInfo.Prefix)
			found := pflag.CommandLine.Lookup(name) != nil
			if !found {
				// Take first line of help only
				help := strings.TrimSpace(opt.Help)
				if nl := strings.IndexRune(help, '\n'); nl >= 0 {
					help = help[:nl]
				}
				help = strings.TrimSpace(help)
				if opt.IsPassword {
					help += " (obscured)"
				}
				flag := pflag.CommandLine.VarPF(opt, name, opt.ShortOpt, help)
				if _, isBool := opt.Default.(bool); isBool {
					flag.NoOptDefVal = "true"
				}
				// Hide on the command line if requested
				if opt.Hide&fs.OptionHideCommandLine != 0 {
					flag.Hidden = true
				}
				backendFlags[name] = struct{}{}
			} else {
				fs.Errorf(nil, "Not adding duplicate flag --%s", name)
			}
			//flag.Hidden = true
		}
	}
}

// Main runs rclone interpreting flags and commands out of os.Args
func Main() {
	rand.Seed(time.Now().Unix())
	setupRootCommand(Root)
	AddBackendFlags()
	if err := Root.Execute(); err != nil {
		log.Fatalf("Fatal error: %v", err)
	}
}
