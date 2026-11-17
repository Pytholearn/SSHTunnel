// Command genicon draws the app and tray icons (a tunnel arch on a rounded
// square) and writes them as PNG/ICO. Run from the repo root:
//
//	go run ./tools/genicon
package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
)

type palette struct{ bg, arch, hole color.RGBA }

var (
	blue  = palette{color.RGBA{37, 99, 235, 255}, color.RGBA{255, 255, 255, 255}, color.RGBA{15, 23, 42, 255}}
	green = palette{color.RGBA{22, 163, 74, 255}, color.RGBA{255, 255, 255, 255}, color.RGBA{15, 23, 42, 255}}
	grey  = palette{color.RGBA{100, 116, 139, 255}, color.RGBA{241, 245, 249, 255}, color.RGBA{30, 41, 59, 255}}
)

// shape returns which layer a point (0..1 coords) belongs to: 0 none, 1 bg, 2 arch, 3 hole.
func shape(x, y float64) int {
	// rounded square, radius 0.22
	r := 0.22
	dx := math.Max(math.Max(r-x, x-(1-r)), 0)
	dy := math.Max(math.Max(r-y, y-(1-r)), 0)
	if dx*dx+dy*dy > r*r {
		return 0
	}
	inArch := func(cx, cy, rad, bottom float64) bool {
		if y >= cy && y <= bottom && math.Abs(x-cx) <= rad {
			return true
		}
		return y < cy && (x-cx)*(x-cx)+(y-cy)*(y-cy) <= rad*rad
	}
	if inArch(0.5, 0.52, 0.17, 0.80) {
		return 3
	}
	if inArch(0.5, 0.52, 0.31, 0.80) {
		return 2
	}
	return 1
}

func draw(size int, p palette) *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, size, size))
	const ss = 4
	for py := 0; py < size; py++ {
		for px := 0; px < size; px++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					x := (float64(px) + (float64(sx)+0.5)/ss) / float64(size)
					y := (float64(py) + (float64(sy)+0.5)/ss) / float64(size)
					var c color.RGBA
					switch shape(x, y) {
					case 0:
						continue
					case 1:
						c = p.bg
					case 2:
						c = p.arch
					case 3:
						c = p.hole
					}
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
					a++
				}
			}
			if a == 0 {
				continue
			}
			n := float64(ss * ss)
			img.SetRGBA(px, py, color.RGBA{uint8(r / a * a / n), uint8(g / a * a / n), uint8(b / a * a / n), uint8(255 * a / n)})
		}
	}
	return img
}

func pngBytes(img image.Image) []byte {
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// ico packs PNG images (Vista+ format).
func ico(p palette, sizes ...int) []byte {
	var imgs [][]byte
	for _, s := range sizes {
		imgs = append(imgs, pngBytes(draw(s, p)))
	}
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, []uint16{0, 1, uint16(len(sizes))})
	off := 6 + 16*len(sizes)
	for i, s := range sizes {
		w := byte(s)
		if s >= 256 {
			w = 0
		}
		buf.Write([]byte{w, w, 0, 0})
		binary.Write(&buf, binary.LittleEndian, []uint16{1, 32})
		binary.Write(&buf, binary.LittleEndian, []uint32{uint32(len(imgs[i])), uint32(off)})
		off += len(imgs[i])
	}
	for _, b := range imgs {
		buf.Write(b)
	}
	return buf.Bytes()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	must(os.MkdirAll("build/windows", 0o755))
	must(os.MkdirAll("assets", 0o755))
	must(os.WriteFile("build/appicon.png", pngBytes(draw(1024, blue)), 0o644))
	must(os.WriteFile("build/windows/icon.ico", ico(blue, 16, 24, 32, 48, 64, 256), 0o644))
	must(os.WriteFile("assets/tray_on.ico", ico(green, 16, 20, 24, 32, 48), 0o644))
	must(os.WriteFile("assets/tray_off.ico", ico(grey, 16, 20, 24, 32, 48), 0o644))
	must(os.WriteFile("frontend/dist/icon.png", pngBytes(draw(128, blue)), 0o644))
}
