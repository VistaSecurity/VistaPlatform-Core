package services

import (
	"bytes"
	"encoding/binary"
	"errors"
	"image"
	"image/jpeg"
	"image/png"
	"testing"

	"github.com/google/uuid"
)

func riff(chunk string, payload []byte) []byte {
	var b bytes.Buffer
	b.WriteString("RIFF")
	_ = binary.Write(&b, binary.LittleEndian, uint32(4+8+len(payload)))
	b.WriteString("WEBP")
	b.WriteString(chunk)
	_ = binary.Write(&b, binary.LittleEndian, uint32(len(payload)))
	b.Write(payload)
	return b.Bytes()
}

func TestSniffImage(t *testing.T) {
	var p, j bytes.Buffer
	_ = png.Encode(&p, image.NewRGBA(image.Rect(0, 0, 7, 3)))
	_ = jpeg.Encode(&j, image.NewRGBA(image.Rect(0, 0, 9, 4)), nil)
	// VP8X 640x480 (canvas width-1 / height-1, 24-bit LE).
	vp8x := make([]byte, 10+8)
	vp8x[4], vp8x[5] = 0x7f, 0x02 // 639
	vp8x[7], vp8x[8] = 0xdf, 0x01 // 479
	// VP8L 16x8: signature 0x2f then (w-1) | (h-1)<<14.
	vp8l := make([]byte, 5+8)
	vp8l[0] = 0x2f
	binary.LittleEndian.PutUint32(vp8l[1:], uint32(15)|uint32(7)<<14)
	// VP8 lossy 33x17.
	vp8 := make([]byte, 10+8)
	vp8[3], vp8[4], vp8[5] = 0x9d, 0x01, 0x2a
	binary.LittleEndian.PutUint16(vp8[6:], 33)
	binary.LittleEndian.PutUint16(vp8[8:], 17)

	cases := []struct {
		name string
		data []byte
		ct   string
		w, h int
		err  error
	}{
		{"png", p.Bytes(), "image/png", 7, 3, nil},
		{"jpeg", j.Bytes(), "image/jpeg", 9, 4, nil},
		{"webp vp8x", riff("VP8X", vp8x), "image/webp", 640, 480, nil},
		{"webp vp8l", riff("VP8L", vp8l), "image/webp", 16, 8, nil},
		{"webp vp8", riff("VP8 ", vp8), "image/webp", 33, 17, nil},
		{"svg size", []byte(`<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg" width="120px" height="60"/>`), "image/svg+xml", 120, 60, nil},
		{"svg viewBox", []byte(`<svg viewBox="0 0 200 100" xmlns="http://www.w3.org/2000/svg"></svg>`), "image/svg+xml", 200, 100, nil},
		{"svg no size", []byte(`<svg xmlns="http://www.w3.org/2000/svg"></svg>`), "image/svg+xml", 300, 150, nil},
		{"svg script", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>1</script></svg>`), "", 0, 0, ErrImageUnsupported},
		{"svg handler", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="x()"></svg>`), "", 0, 0, ErrImageUnsupported},
		{"svg foreignObject", []byte(`<svg xmlns="http://www.w3.org/2000/svg"><foreignObject/></svg>`), "", 0, 0, ErrImageUnsupported},
		{"exe", []byte("MZ\x90\x00\x03"), "", 0, 0, ErrImageUnsupported},
		{"html", []byte("<html><body>hi</body></html>"), "", 0, 0, ErrImageUnsupported},
		{"empty", nil, "", 0, 0, ErrImageInvalid},
		{"truncated png", p.Bytes()[:12], "", 0, 0, ErrImageInvalid},
		{"too large", append(p.Bytes(), make([]byte, MaxImageBytes)...), "", 0, 0, ErrImageTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := sniffImage(c.data)
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
			if c.err == nil && (got.ContentType != c.ct || got.Width != c.w || got.Height != c.h) {
				t.Fatalf("got %+v, want %s %dx%d", got, c.ct, c.w, c.h)
			}
		})
	}
}

func TestBlobStore_LocalRefsAreTenantScoped(t *testing.T) {
	b := NewBlobStore(nil, t.TempDir())
	ta, tb := newTestUUID(1), newTestUUID(2)
	ref, err := b.Put(t.Context(), ta, "11111111-1111-1111-1111-111111111111.png", "image/png", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if rc, err := b.Open(t.Context(), ta, ref); err != nil {
		t.Fatal(err)
	} else {
		_ = rc.Close()
	}
	if _, err := b.Open(t.Context(), tb, ref); err == nil {
		t.Fatal("another tenant opened the image")
	}
	for _, bad := range []string{"local:../../etc/passwd", "local:" + ta.String() + "/../x.png", "local:" + ta.String() + "/not-a-uuid.png"} {
		if _, err := b.Open(t.Context(), ta, bad); err == nil {
			t.Fatalf("opened %q", bad)
		}
	}
	if err := b.Delete(t.Context(), ta, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Open(t.Context(), ta, ref); err == nil {
		t.Fatal("deleted image still opens")
	}
}

func newTestUUID(n byte) uuid.UUID { return uuid.UUID{n} }
