package ai

import (
	"fmt"
	"io"
	"sort"
	"strconv"
)

// The helpers behind PromptHash. They exist to make the digest depend on the
// STRUCTURE of a request and not on the accidents of how Go happens to walk it
// — map order, in particular, which is randomised per process and would
// otherwise give the same prompt a different hash on every call, turning the
// audit trail's most useful column into noise.

// writeField writes a length-prefixed string. The prefix is what stops
// ("ab", "c") and ("a", "bc") from hashing alike.
func writeField(h io.Writer, s string) {
	writeLen(h, len(s))
	_, _ = io.WriteString(h, s)
}

func writeLen(h io.Writer, n int) {
	_, _ = io.WriteString(h, strconv.Itoa(n))
	_, _ = io.WriteString(h, "\x00")
}

// hashMap writes a map in sorted-key order, recursing into nested maps and
// slices so a change anywhere in the grounding context changes the digest.
func hashMap(h io.Writer, m map[string]any) {
	writeLen(h, len(m))

	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		writeField(h, k)
		hashValue(h, m[k])
	}
}

func hashValue(h io.Writer, v any) {
	switch typed := v.(type) {
	case map[string]any:
		_, _ = io.WriteString(h, "m")
		hashMap(h, typed)
	case []any:
		_, _ = io.WriteString(h, "s")
		writeLen(h, len(typed))
		for _, item := range typed {
			hashValue(h, item)
		}
	case []map[string]any:
		_, _ = io.WriteString(h, "s")
		writeLen(h, len(typed))
		for _, item := range typed {
			_, _ = io.WriteString(h, "m")
			hashMap(h, item)
		}
	case string:
		_, _ = io.WriteString(h, "t")
		writeField(h, typed)
	default:
		// %v over a scalar is stable for every JSON-decodable type we carry
		// here. A type tag keeps the string "42" from hashing like the number
		// 42, which matters because one of them may be a redaction marker and
		// the other a key size.
		_, _ = io.WriteString(h, "v")
		writeField(h, fmt.Sprintf("%T:%v", v, v))
	}
}
