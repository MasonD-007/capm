package main

import (
	"crypto/x509"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

func certSummary(c *x509.Certificate) (certificate.Summary, error) {
	return certificate.SummarizeCertificate(c)
}
