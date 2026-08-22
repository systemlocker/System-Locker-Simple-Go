package simple

// googleSsoPortal is the fixed entry point of the Google SSO flow. The
// server embeds this URL in sso/ssoexp/ssowrong denial reasons; the client
// mirrors it so the flow can start before a denial is ever seen.
const googleSsoPortal = "https://systemlocker.net/user/sso?system="

// GoogleSsoURL returns the Google SSO portal URL for a system. After the
// user signs in there, the portal shows a system-specific password that is
// valid for 180 days and is then used as the account password.
//
// The Simple protocol targets trusted machines (typically servers), so the
// library deliberately stops at the URL: route it to your user through your
// own channel (API response, email, chat) rather than expecting a browser
// on the host.
func GoogleSsoURL(systemID string) string {
	return googleSsoPortal + escapeSystemID(systemID)
}

// GoogleSsoURL returns the portal URL for the client's configured system.
func (c *Client) GoogleSsoURL() string {
	return GoogleSsoURL(c.config.SystemID)
}

// escapeSystemID percent-encodes everything except unreserved characters,
// matching the server's rawurlencode so every client builds byte-identical
// portal URLs.
func escapeSystemID(value string) string {
	const hexDigits = "0123456789ABCDEF"
	var encoded []byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			encoded = append(encoded, c)
		default:
			encoded = append(encoded, '%', hexDigits[c>>4], hexDigits[c&0x0F])
		}
	}
	return string(encoded)
}
