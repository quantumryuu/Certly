package pki

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// RFC 5280 revocation reason codes we offer.
const (
	ReasonUnspecified          = 0
	ReasonKeyCompromise        = 1
	ReasonCACompromise         = 2
	ReasonAffiliationChanged   = 3
	ReasonSuperseded           = 4
	ReasonCessationOfOperation = 5
	ReasonCertificateHold      = 6 // not offered: holds are not supported
	ReasonPrivilegeWithdrawn   = 9
)

// Reasons maps the reason codes users can pick to labels.
var Reasons = []struct {
	Code  int
	Label string
}{
	{ReasonUnspecified, "Unspecified"},
	{ReasonKeyCompromise, "Key compromise"},
	{ReasonCACompromise, "CA compromise"},
	{ReasonAffiliationChanged, "Affiliation changed"},
	{ReasonSuperseded, "Superseded"},
	{ReasonCessationOfOperation, "Cessation of operation"},
	{ReasonPrivilegeWithdrawn, "Privilege withdrawn"},
}

// ValidReason reports whether code is one of Reasons.
func ValidReason(code int) bool {
	for _, r := range Reasons {
		if r.Code == code {
			return true
		}
	}
	return false
}

// ReasonLabel returns the label for a reason code.
func ReasonLabel(code int) string {
	for _, r := range Reasons {
		if r.Code == code {
			return r.Label
		}
	}
	return fmt.Sprintf("Reason %d", code)
}

// Revoked is one entry in a CRL.
type Revoked struct {
	Serial    *big.Int
	RevokedAt time.Time
	Reason    int
}

// BuildCRL creates a CRL signed by the CA. number must increase with every
// CRL the CA publishes.
func BuildCRL(ca *Signer, entries []Revoked, number int64, thisUpdate time.Time, validity time.Duration) ([]byte, error) {
	if ca == nil || !ca.Cert.IsCA || ca.Cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return nil, errors.New("pki: CRL signer is not a CA with cRLSign")
	}
	if validity <= 0 {
		return nil, errors.New("pki: CRL validity must be positive")
	}
	list := make([]x509.RevocationListEntry, 0, len(entries))
	for _, e := range entries {
		entry := x509.RevocationListEntry{SerialNumber: e.Serial, RevocationTime: e.RevokedAt.UTC()}
		if e.Reason != ReasonUnspecified {
			entry.ReasonCode = e.Reason
		}
		list = append(list, entry)
	}
	nextUpdate := thisUpdate.Add(validity)
	if nextUpdate.After(ca.Cert.NotAfter) {
		nextUpdate = ca.Cert.NotAfter
	}
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                thisUpdate.UTC(),
		NextUpdate:                nextUpdate.UTC(),
		RevokedCertificateEntries: list,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca.Cert, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign CRL: %w", err)
	}
	return der, nil
}
