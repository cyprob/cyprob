package scan

import (
	"encoding/hex"
	"math/big"
	"strings"
)

// FormatCertificateSerial renders a certificate serial as uppercase
// colon-separated hex, the form OpenSSL prints.
//
// It is exported because three call sites write the same tls_cert_serial
// column: this package's TLS probe, and cyprob-ee's two SSL template paths
// (adapter_ssl_template.go and executor_ssl_template_plugin.go), which used to
// carry byte-identical private copies of this function. A column carrying two
// encodings is worse than one carrying a single imperfect encoding, because a
// reader cannot ask which one it got — so the encoding lives here, once, and
// cyprob-ee calls it through the module it already imports (cyprob#302).
//
// A negative serial keeps its sign. big.Int.Bytes() returns the magnitude, so
// the sign has to be put back by hand; without that, two certificates whose
// serials differ only in sign render identically.
//
// Note what that branch is worth today, so nobody deletes it as dead or
// oversells it as a field fix: RFC 5280 §4.1.2.2 requires a positive serial,
// and since Go 1.23 crypto/x509 enforces it — ParseCertificate rejects a
// negative serial outright ("x509: negative serial number"), which fails the
// whole handshake, not just the serial read. Both repositories build at
// go 1.25 with no godebug directive, so no certificate reaching any of the
// three call sites can carry a negative serial unless GODEBUG
// x509negativeserial=1 is set. The branch is here because this function's
// input is a *big.Int, which admits one, and because the alternative — the
// hex differing between two producers of one column — is the failure this
// function exists to prevent. It is not here because it repairs stored data.
func FormatCertificateSerial(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	raw := serial.Bytes()
	if len(raw) == 0 {
		return ""
	}
	encoded := strings.ToUpper(hex.EncodeToString(raw))
	parts := make([]string, 0, len(encoded)/2)
	for i := 0; i < len(encoded); i += 2 {
		parts = append(parts, encoded[i:i+2])
	}
	formatted := strings.Join(parts, ":")
	if serial.Sign() < 0 {
		return "-" + formatted
	}
	return formatted
}
