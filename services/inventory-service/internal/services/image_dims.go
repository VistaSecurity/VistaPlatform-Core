package services

// Image sniffing for image attachments (DCIM BUILD_PLAN row 2.8): the type is
// decided from the bytes, never from the file name or the client's
// Content-Type, and the pixel (or viewBox) size is read from the header. Four
// types are accepted: png, jpeg, webp, svg.

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"image"
	_ "image/jpeg" // registers the jpeg decoder for image.DecodeConfig
	_ "image/png"  // registers the png decoder for image.DecodeConfig
	"io"
	"regexp"
	"strconv"
	"strings"
)

// MaxImageBytes is the largest image an attachment may be.
const MaxImageBytes = 5 << 20

// Errors the handlers map onto statuses.
var (
	ErrImageTooLarge    = errors.New("image is larger than 5 MB")
	ErrImageUnsupported = errors.New("only png, jpeg, webp and svg images are accepted")
	ErrImageInvalid     = errors.New("image is not readable")
)

// imageInfo is what the sniff learned.
type imageInfo struct {
	ContentType string // image/png, image/jpeg, image/webp, image/svg+xml
	Ext         string // .png, .jpg, .webp, .svg
	Width       int
	Height      int
}

func sniffImage(data []byte) (imageInfo, error) {
	if len(data) == 0 {
		return imageInfo{}, ErrImageInvalid
	}
	if len(data) > MaxImageBytes {
		return imageInfo{}, ErrImageTooLarge
	}
	switch {
	case bytes.HasPrefix(data, []byte("\x89PNG\r\n\x1a\n")):
		return rasterInfo(data, "image/png", ".png")
	case bytes.HasPrefix(data, []byte("\xff\xd8\xff")):
		return rasterInfo(data, "image/jpeg", ".jpg")
	case len(data) >= 12 && string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP":
		w, h, err := webpSize(data)
		if err != nil {
			return imageInfo{}, err
		}
		return imageInfo{ContentType: "image/webp", Ext: ".webp", Width: w, Height: h}, nil
	}
	if looksLikeSVG(data) {
		w, h, err := svgSize(data)
		if err != nil {
			return imageInfo{}, err
		}
		return imageInfo{ContentType: "image/svg+xml", Ext: ".svg", Width: w, Height: h}, nil
	}
	return imageInfo{}, ErrImageUnsupported
}

func rasterInfo(data []byte, ct, ext string) (imageInfo, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil || cfg.Width <= 0 || cfg.Height <= 0 {
		return imageInfo{}, ErrImageInvalid
	}
	return imageInfo{ContentType: ct, Ext: ext, Width: cfg.Width, Height: cfg.Height}, nil
}

func webpSize(d []byte) (int, int, error) {
	if len(d) < 30 {
		return 0, 0, ErrImageInvalid
	}
	switch string(d[12:16]) {
	case "VP8 ": // lossy: frame header at 20, start code 9d 01 2a at 23
		if len(d) < 30 || d[23] != 0x9d || d[24] != 0x01 || d[25] != 0x2a {
			return 0, 0, ErrImageInvalid
		}
		w := int(binary.LittleEndian.Uint16(d[26:28]) & 0x3fff)
		h := int(binary.LittleEndian.Uint16(d[28:30]) & 0x3fff)
		return w, h, positive(w, h)
	case "VP8L": // lossless: signature 0x2f at 20, then 14+14 bits
		if d[20] != 0x2f {
			return 0, 0, ErrImageInvalid
		}
		b := binary.LittleEndian.Uint32(d[21:25])
		w := int(b&0x3fff) + 1
		h := int((b>>14)&0x3fff) + 1
		return w, h, positive(w, h)
	case "VP8X": // extended: 24-bit canvas width-1 / height-1 at 24 and 27
		w := int(uint32(d[24])|uint32(d[25])<<8|uint32(d[26])<<16) + 1
		h := int(uint32(d[27])|uint32(d[28])<<8|uint32(d[29])<<16) + 1
		return w, h, positive(w, h)
	}
	return 0, 0, ErrImageInvalid
}

func positive(w, h int) error {
	if w <= 0 || h <= 0 {
		return ErrImageInvalid
	}
	return nil
}

func looksLikeSVG(data []byte) bool {
	head := data
	if len(head) > 2048 {
		head = head[:2048]
	}
	return bytes.Contains(bytes.ToLower(head), []byte("<svg"))
}

var svgActive = regexp.MustCompile(`(?i)<\s*(script|foreignobject|iframe|embed|object)\b|\son[a-z]+\s*=|javascript:`)

var svgLen = regexp.MustCompile(`^\s*([0-9]*\.?[0-9]+)\s*(px|pt|mm|cm|in|em|)\s*$`)

// svgSize reads the root element's size. An SVG that carries script, an event
// handler or an embedded active element is refused outright rather than
// sanitised; it is also served with a sandboxing CSP.
func svgSize(data []byte) (int, int, error) {
	if svgActive.Match(data) {
		return 0, 0, fmt.Errorf("%w: svg images may not contain scripts, event handlers or embedded objects", ErrImageUnsupported)
	}
	dec := xml.NewDecoder(bytes.NewReader(data))
	dec.Strict = false
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, 0, ErrImageInvalid
			}
			return 0, 0, ErrImageInvalid
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if !strings.EqualFold(se.Name.Local, "svg") {
			return 0, 0, ErrImageInvalid
		}
		attr := map[string]string{}
		for _, a := range se.Attr {
			attr[strings.ToLower(a.Name.Local)] = a.Value
		}
		w, h := svgLength(attr["width"]), svgLength(attr["height"])
		if vb := strings.Fields(strings.NewReplacer(",", " ").Replace(attr["viewbox"])); len(vb) == 4 {
			vw, _ := strconv.ParseFloat(vb[2], 64)
			vh, _ := strconv.ParseFloat(vb[3], 64)
			if w == 0 {
				w = int(vw + 0.5)
			}
			if h == 0 {
				h = int(vh + 0.5)
			}
		}
		if w <= 0 || h <= 0 {
			// No intrinsic size declared (the width and height columns must be
			// positive): record the nominal 300x150 browsers give such an image.
			w, h = 300, 150
		}
		return w, h, nil
	}
}

func svgLength(s string) int {
	m := svgLen.FindStringSubmatch(s)
	if m == nil {
		return 0
	}
	f, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0
	}
	return int(f + 0.5)
}
