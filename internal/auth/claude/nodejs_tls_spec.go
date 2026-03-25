// Package claude 提供 Anthropic Claude API 的认证功能。
// 本文件定义了精确还原 Node.js (OpenSSL 3.x) TLS ClientHello 指纹的自定义 ClientHelloSpec。
//
// 数据来源：抓包 Node.js v22.21.1 / OpenSSL 3.0.13 到 api.anthropic.com 的 TLS ClientHello。
// 与 Chrome (BoringSSL) 的关键差异：
//   - 无 GREASE 值占位
//   - 52 个密码套件（Chrome 约 15 个）
//   - TLS 1.3 密码套件 AES-256 优先（Chrome AES-128 优先）
//   - 11 个扩展（Chrome 约 16 个）
//   - 包含 encrypt_then_mac 扩展（Chrome 无）
//   - 不包含 compress_certificate、application_settings 等 Chrome 特有扩展
//   - supported_groups 含 MLKEM768_X25519 后量子混合密钥交换、x448 和 FFDHE 组
//   - 26 个签名算法（Chrome 约 9 个）
package claude

import (
	tls "github.com/refraction-networking/utls"
)

// nodejsClientHelloSpec 返回精确还原 Node.js v22.x (OpenSSL 3.0.x) 的自定义 ClientHelloSpec。
// 所有密码套件、扩展及其顺序均来自真实抓包数据，确保 TLS 指纹与真实 Node.js 客户端一致。
func nodejsClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		TLSVersMax: tls.VersionTLS13,
		TLSVersMin: tls.VersionTLS12,
		// 52 个密码套件，顺序精确还原自 OpenSSL 3.0.x 默认配置。
		// 关键差异：TLS 1.3 中 AES-256-GCM 排在 AES-128-GCM 前面（Chrome 相反）。
		CipherSuites: []uint16{
			// TLS 1.3 密码套件（OpenSSL 默认顺序：AES-256 优先）
			tls.TLS_AES_256_GCM_SHA384,           // 0x1302
			tls.TLS_CHACHA20_POLY1305_SHA256,      // 0x1303
			tls.TLS_AES_128_GCM_SHA256,            // 0x1301
			// TLS 1.2 密码套件（OpenSSL 默认顺序）
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,    // 0xC02F
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,  // 0xC02B
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,    // 0xC030
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,  // 0xC02C
			0x009E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,     // 0xC027
			0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
			0xC028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0x006B, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
			0x00A3, // TLS_DHE_DSS_WITH_AES_256_GCM_SHA384
			0x009F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // 0xCCA9
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // 0xCCA8
			0xCCAA, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			0xC0AD, // TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
			0xC09F, // TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384
			0xC05D, // TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
			0xC061, // TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384
			0xC057, // TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xC053, // TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
			0x00A2, // TLS_DHE_DSS_WITH_AES_128_GCM_SHA256
			0xC0AC, // TLS_ECDHE_ECDSA_WITH_AES_128_CCM
			0xC09E, // TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xC05C, // TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
			0xC060, // TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256
			0xC056, // TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256
			0xC052, // TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256
			0xC024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0x006A, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, // 0xC023
			0x0040, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,    // 0xC00A
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,      // 0xC014
			0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			0x0038, // TLS_DHE_DSS_WITH_AES_256_CBC_SHA
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,    // 0xC009
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,      // 0xC013
			0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			0x0032, // TLS_DHE_DSS_WITH_AES_128_CBC_SHA
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,         // 0x009D
			0xC09D, // TLS_RSA_WITH_AES_256_CCM
			0xC051, // TLS_RSA_WITH_ARIA_256_GCM_SHA384
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,         // 0x009C
			0xC09C, // TLS_RSA_WITH_AES_128_CCM
			0xC050, // TLS_RSA_WITH_ARIA_128_GCM_SHA256
			0x003D, // TLS_RSA_WITH_AES_256_CBC_SHA256
			0x003C, // TLS_RSA_WITH_AES_128_CBC_SHA256
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,             // 0x0035
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,             // 0x002F
		},
		CompressionMethods: []byte{0x00}, // null compression only
		// 11 个扩展，顺序精确还原自抓包数据。
		Extensions: []tls.TLSExtension{
			// 0xFF01 - renegotiation_info
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			// 0x0000 - server_name (SNI) — 由 utls 自动填充
			&tls.SNIExtension{},
			// 0x000B - ec_point_formats [uncompressed, ansiX962_compressed_prime, ansiX962_compressed_char2]
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0x00, 0x01, 0x02}},
			// 0x000A - supported_groups
			// 含后量子混合密钥交换 MLKEM768_X25519 (0x11EC)、x448 和 FFDHE 组，
			// 匹配 Node.js v22.x / OpenSSL 3.0.x 默认配置。
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768,                // 0x11EC - 后量子混合密钥交换
				tls.X25519,                        // 0x001D
				tls.CurveP256,                     // 0x0017
				tls.CurveID(0x001E),               // x448
				tls.CurveP384,                     // 0x0018
				tls.CurveP521,                     // 0x0019
				tls.CurveID(tls.FakeCurveFFDHE2048), // 0x0100
				tls.CurveID(tls.FakeCurveFFDHE3072), // 0x0101
			}},
			// 0x0023 - session_ticket
			&tls.SessionTicketExtension{},
			// 0x0010 - ALPN（协商 HTTP/2 所必需）
			// 抓包中 Node.js https 模块未发送 ALPN，但 utlsRoundTripper 需要 HTTP/2，
			// 若不声明 h2，服务器将回退 HTTP/1.1 导致帧解析失败。
			&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
			// 0x0016 - encrypt_then_mac（OpenSSL 特有，Chrome 不发送此扩展）
			// utls 没有内置此扩展类型，使用 GenericExtension 实现
			&tls.GenericExtension{Id: 0x0016, Data: []byte{}},
			// 0x0017 - extended_master_secret
			&tls.ExtendedMasterSecretExtension{},
			// 0x000D - signature_algorithms（26 个，OpenSSL 3.0.x 默认集）
			// 使用原始数值以精确匹配抓包数据，避免 utls 常量命名歧义
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				0x0905, // ecdsa_brainpoolP384r1tls13_sha384
				0x0906, // ecdsa_brainpoolP512r1tls13_sha512
				0x0904, // ecdsa_brainpoolP256r1tls13_sha256
				0x0403, // ecdsa_secp256r1_sha256
				0x0503, // ecdsa_secp384r1_sha384
				0x0603, // ecdsa_secp521r1_sha512
				0x0807, // ed25519
				0x0808, // ed448
				0x081A, // rsa_pss_rsae_sha256 (CertificateVerify, OpenSSL 3.x)
				0x081B, // rsa_pss_rsae_sha384 (CertificateVerify, OpenSSL 3.x)
				0x081C, // rsa_pss_rsae_sha512 (CertificateVerify, OpenSSL 3.x)
				0x0809, // rsa_pss_pss_sha256
				0x080A, // rsa_pss_pss_sha384
				0x080B, // rsa_pss_pss_sha512
				0x0804, // rsa_pss_rsae_sha256
				0x0805, // rsa_pss_rsae_sha384
				0x0806, // rsa_pss_rsae_sha512
				0x0401, // rsa_pkcs1_sha256
				0x0501, // rsa_pkcs1_sha384
				0x0601, // rsa_pkcs1_sha512
				0x0303, // ecdsa_sha1 (legacy)
				0x0301, // rsa_pkcs1_sha1 (legacy)
				0x0302, // dsa_sha1 (legacy)
				0x0402, // dsa_sha256
				0x0502, // dsa_sha384
				0x0602, // dsa_sha512
			}},
			// 0x002B - supported_versions [TLS 1.3, TLS 1.2]
			&tls.SupportedVersionsExtension{Versions: []uint16{
				tls.VersionTLS13, // 0x0304
				tls.VersionTLS12, // 0x0303
			}},
			// 0x002D - psk_key_exchange_modes [psk_dhe_ke(1)]
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
			// 0x0033 - key_share
			// utls 会自动为列出的组生成密钥交换数据。
			// 抓包显示 Node.js 发送了 MLKEM768_X25519 和 x25519 两个 key_share。
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768}, // 0x11EC - 后量子混合（1216 字节密钥）
				{Group: tls.X25519},         // 0x001D（32 字节密钥）
			}},
		},
	}
}
