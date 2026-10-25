// Package i18n provides a minimal English/Spanish string table for hodor's
// user-facing pages (closed page, TV pass page, admin panel). There is no
// pluralization or ICU support on purpose: hodor only needs a handful of
// short strings.
package i18n

// Lang is a supported UI language code.
type Lang string

const (
	EN Lang = "en"
	ES Lang = "es"
)

// Default is used when the configured language is empty or unknown.
const Default = EN

var strings = map[string]map[Lang]string{
	"closed.title": {
		EN: "Service closed",
		ES: "Servicio cerrado",
	},
	"closed.ask": {
		EN: "Ask someone at home to open it.",
		ES: "Pide a alguien de casa que lo abra.",
	},
	"closed.admin_button": {
		EN: "Open admin panel",
		ES: "Abrir panel de administración",
	},
	"tv.title": {
		EN: "Device pass",
		ES: "Pase de dispositivo",
	},
	"tv.enter_pin": {
		EN: "Enter this PIN on the admin panel to pair this device:",
		ES: "Introduce este PIN en el panel de administración para emparejar este dispositivo:",
	},
	"tv.expires": {
		EN: "This PIN expires in 10 minutes.",
		ES: "Este PIN caduca en 10 minutos.",
	},
	"tv.qr_todo": {
		EN: "QR code not available in this build, use the PIN above.",
		ES: "Código QR no disponible en esta versión, usa el PIN de arriba.",
	},
	"panel.title": {
		EN: "hodor — admin panel",
		ES: "hodor — panel de administración",
	},
}

// T returns the translated string for key in lang, falling back to EN and
// finally to the key itself if nothing is found.
func T(lang Lang, key string) string {
	set, ok := strings[key]
	if !ok {
		return key
	}
	if v, ok := set[lang]; ok {
		return v
	}
	if v, ok := set[EN]; ok {
		return v
	}
	return key
}

// Parse normalizes a config language string into a known Lang, defaulting
// to Default when unrecognized.
func Parse(s string) Lang {
	switch Lang(s) {
	case EN, ES:
		return Lang(s)
	default:
		return Default
	}
}
