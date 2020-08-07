// Internal tests for operations

package operations

import (
	"fmt"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/object"
	"github.com/stretchr/testify/assert"
)

func TestSizeDiffers(t *testing.T) {
	when := time.Now()
	for _, test := range []struct {
		ignoreSize bool
		srcSize    int64
		dstSize    int64
		want       bool
	}{
		{false, 0, 0, false},
		{false, 1, 2, true},
		{false, 1, -1, false},
		{false, -1, 1, false},
		{true, 0, 0, false},
		{true, 1, 2, false},
		{true, 1, -1, false},
		{true, -1, 1, false},
	} {
		src := object.NewStaticObjectInfo("a", when, test.srcSize, true, nil, nil)
		dst := object.NewStaticObjectInfo("a", when, test.dstSize, true, nil, nil)
		oldIgnoreSize := fs.Config.IgnoreSize
		fs.Config.IgnoreSize = test.ignoreSize
		got := sizeDiffers(src, dst)
		fs.Config.IgnoreSize = oldIgnoreSize
		assert.Equal(t, test.want, got, fmt.Sprintf("ignoreSize=%v, srcSize=%v, dstSize=%v", test.ignoreSize, test.srcSize, test.dstSize))
	}
}
