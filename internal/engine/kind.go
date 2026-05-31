package engine

import "strings"

// kindFromService maps an mDNS service kind (and optional model from TXT records) to a device
// label. A non-empty service kind wins; otherwise we try to read the model.
func kindFromService(serviceKind, model string) string {
	if serviceKind != "" {
		return serviceKind
	}
	return kindFromModel(model)
}

// kindFromModel maps an Apple-style model identifier to a friendly device type.
func kindFromModel(model string) string {
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "macbook"):
		return "Laptop (Mac)"
	case strings.HasPrefix(m, "imac"), strings.HasPrefix(m, "macmini"),
		strings.HasPrefix(m, "macpro"), strings.HasPrefix(m, "mac"):
		return "Mac"
	case strings.HasPrefix(m, "iphone"):
		return "iPhone"
	case strings.HasPrefix(m, "ipad"):
		return "iPad"
	case strings.HasPrefix(m, "appletv"):
		return "Apple TV"
	case strings.HasPrefix(m, "watch"):
		return "Apple Watch"
	}
	return ""
}

// kindFromVendor is the weakest signal: a coarse guess from the hardware vendor when nothing
// stronger identified the device.
func kindFromVendor(vendor string) string {
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "apple"):
		return "Apple device"
	case strings.Contains(v, "samsung"):
		return "Samsung device"
	case strings.Contains(v, "google"):
		return "Google device"
	case strings.Contains(v, "amazon"):
		return "Amazon device"
	case strings.Contains(v, "raspberry"):
		return "Raspberry Pi"
	case strings.Contains(v, "huawei"), strings.Contains(v, "xiaomi"), strings.Contains(v, "oppo"):
		return "Mobile"
	}
	return ""
}
