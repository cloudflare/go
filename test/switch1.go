// $G $F.go && $L $F.$A && ./$A.out

// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

func main() {
	i := 0;
	switch x := 5; {
		case i < x:
			sys.Exit(0);
		case i == x:
		case i > x:
			sys.Exit(1);
	}
}
