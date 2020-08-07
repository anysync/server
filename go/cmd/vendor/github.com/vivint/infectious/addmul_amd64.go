// The MIT License (MIT)
//
// Copyright (C) 2016-2017 Vivint, Inc.
// Copyright (c) 2015 Klaus Post
// Copyright (c) 2015 Backblaze
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package infectious

//go:noescape
func addmulSSSE3(lowhigh *pair, in, out *byte, n int, mul *byte)

//go:noescape
func addmulAVX2(lowhigh *pair, in, out *byte, n int)

func addmul(z, x []byte, y byte) {
	if len(z) == 0 {
		return
	}

	var done int
	if hasAVX2 {
		addmulAVX2(&mul_table_pair[y], &x[0], &z[0], len(z))
		done = (len(x) >> 5) << 5
	} else if hasSSSE3 {
		addmulSSSE3(&mul_table_pair[y], &x[0], &z[0], len(z), &gf_mul_table[y][0])
		//done = (len(x) >> 4) << 4
		return
	}

	if done < len(z) {
		// hints to the compiler to remove bounds checks
		z = z[done:]
		x = x[done : done+len(z)]

		gf_mul_y := gf_mul_table[y][:]
		for i := range z {
			z[i] ^= gf_mul_y[x[i]]
		}
	}
}
