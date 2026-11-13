// unsnappy decodes a raw snappy block (the format of GitHub attestation
// bundle_url blobs) from argv[1] to argv[2]. Minimal decoder; spike only.
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	in, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	n, k := binary.Uvarint(in)
	in = in[k:]
	out := make([]byte, 0, n)
	for len(in) > 0 {
		tag := in[0]
		switch tag & 3 {
		case 0: // literal
			l := int(tag >> 2)
			in = in[1:]
			switch {
			case l < 60:
			case l == 60:
				l, in = int(in[0]), in[1:]
			case l == 61:
				l, in = int(binary.LittleEndian.Uint16(in)), in[2:]
			default:
				panic("long literal")
			}
			l++
			out = append(out, in[:l]...)
			in = in[l:]
		default:
			var length, off int
			switch tag & 3 {
			case 1:
				length = int(tag>>2&7) + 4
				off = int(tag>>5)<<8 | int(in[1])
				in = in[2:]
			case 2:
				length = int(tag>>2) + 1
				off = int(binary.LittleEndian.Uint16(in[1:]))
				in = in[3:]
			default:
				length = int(tag>>2) + 1
				off = int(binary.LittleEndian.Uint32(in[1:]))
				in = in[5:]
			}
			for i := 0; i < length; i++ {
				out = append(out, out[len(out)-off])
			}
		}
	}
	if uint64(len(out)) != n {
		panic(fmt.Sprintf("length mismatch %d != %d", len(out), n))
	}
	if err := os.WriteFile(os.Args[2], out, 0o644); err != nil {
		panic(err)
	}
}
