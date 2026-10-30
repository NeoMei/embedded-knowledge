package managedcapability

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

type RequestClaims struct {
	Issuer     string `json:"issuer"`
	Audience   string `json:"audience"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	BodySHA256 string `json:"body_sha256"`
	Nonce      string `json:"nonce"`
	WorkID     string `json:"work_id"`
	ActorID    string `json:"actor_id"`
	AccountID  string `json:"account_id"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
}

func (v *Verifier) VerifyRequest(token, method, path string, body []byte, work, actor, account string) (RequestClaims, error) {
	var c RequestClaims
	if v.verifyEnvelope(token, "weknora-request-v1", &c) != nil || c.Issuer != v.issuer || c.Audience != v.audience || method != "POST" || c.Method != method || c.Path != path || !identifier.MatchString(work) || !identifier.MatchString(actor) || !identifier.MatchString(account) || c.WorkID != work || c.ActorID != actor || c.AccountID != account || !digest.MatchString(c.Nonce) || !v.validWindow(c.IssuedAt, c.ExpiresAt, 30) {
		return RequestClaims{}, ErrInvalid
	}
	sum := sha256.Sum256(body)
	if !hmac.Equal([]byte(c.BodySHA256), []byte(hex.EncodeToString(sum[:]))) {
		return RequestClaims{}, ErrInvalid
	}
	return c, nil
}
