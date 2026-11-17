// SPDX-License-Identifier: GPL-3.0-or-later

// Package legacy implements the Snell v2/v3 client record layer and lifecycle.
//
// Wire behavior is adapted from MetaCubeX/mihomo's GPL-3.0 implementation,
// transport/snell/{cipher,snell,pool}.go and
// transport/shadowsocks/shadowaead/stream.go, at commit
// 0455d0d28c4526937380505153e65a843d8612e8:
// https://github.com/MetaCubeX/mihomo/tree/0455d0d28c4526937380505153e65a843d8612e8/transport/snell
//
// The existing sing-snell package supplies request/address serialization and
// HTTP/TLS obfuscation. No mihomo runtime dependency is needed.
package legacy
