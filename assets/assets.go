// Package assets contains branding shared by parallaxd's operator surfaces.
package assets

import _ "embed"

// ParallaxdIconPNG is the icon used by the dashboard and Mattermost delivery.
//
//go:embed parallaxd-icon.png
var ParallaxdIconPNG []byte
