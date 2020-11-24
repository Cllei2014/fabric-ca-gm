package cmd

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"strings"

	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/cloudflare/cfssl/csr"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	kms "github.com/tw-bc-group/aliyun-kms/sm2"
)

const subjectFormatError = "Subject 格式不正确，比如: /C=CN/ST=TJ/L=TJ/O=TEST/OU=TEST/CN=TEST CA"

func appendIfNotEmpty(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}

func NewCsrTemplate(subj string, publicKey *sm2.PublicKey) (*x509GM.CertificateRequest, error) {
	var name pkix.Name

	fields := strings.Split(subj, "/")

	if len(fields) == 0 {
		return nil, errors.New(subjectFormatError)
	}

	for _, field := range fields {
		subFields := strings.Split(field, "=")
		if len(subFields) == 1 {
			continue
		} else if len(subFields) != 2 {
			return nil, errors.New(subjectFormatError)
		}

		switch strings.ToUpper(strings.TrimSpace(subFields[0])) {
		case "C":
			appendIfNotEmpty(subFields[1], &name.Country)
		case "ST":
			appendIfNotEmpty(subFields[1], &name.Province)
		case "L":
			appendIfNotEmpty(subFields[1], &name.Locality)
		case "O":
			appendIfNotEmpty(subFields[1], &name.Organization)
		case "OU":
			appendIfNotEmpty(subFields[1], &name.OrganizationalUnit)
		case "CN":
			name.CommonName = subFields[1]
		default:
			break
		}
	}

	extensions := make([]pkix.Extension, 8)
	basicConstraints, err := asn1.Marshal(csr.BasicConstraints{IsCA: true, MaxPathLen: -1})
	if err != nil {
		return nil, err
	}

	extensions = append(extensions, pkix.Extension{
		Id:       asn1.ObjectIdentifier(x509.OIDExtensionBasicConstraints),
		Value:    basicConstraints,
		Critical: true,
	})

	return &x509GM.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509GM.SM2WithSM3,
		PublicKeyAlgorithm: x509GM.SM2,
		PublicKey:          publicKey,
		Extensions:         extensions,
	}, nil
}

func newCsr(subj, keyID string) error {

	keyAdapter, err := kms.CreateSm2KeyAdapter(keyID, kms.SignAndVerify)
	if err != nil {
		return err
	}

	pubKey, err := keyAdapter.GetPublicKey()
	if err != nil {
		return err
	}

	csrTemp, err := NewCsrTemplate(subj, pubKey)
	if err != nil {
		return err
	}

	cryptoSigner, err := keyAdapter.TryIntoCryptoSigner()
	if err != nil {
		return err
	}

	csrPem, err := x509GM.CreateCertificateRequestToPem(csrTemp, cryptoSigner)
	if err != nil {
		return err
	}

	printOutput(keyAdapter.KeyID(), string(csrPem))
	return nil
}

func NewCsrCmd() *cobra.Command {
	var subj, keyID string

	csrCmd := &cobra.Command{
		Use:   "newcsr",
		Short: "Generate new csr file",
		Long:  "Generate new zhong huan ica csr file",
	}

	csrCmd.Flags().StringVarP(&subj, "subj", "s", "", "设置 CSR 请求中的 Subject 字段（必选）")
	_ = csrCmd.MarkFlagRequired("subj")
	csrCmd.Flags().StringVarP(&keyID, "key", "k", "", "设置使用的 KMS 密钥 ID（可选）")
	csrCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return newCsr(subj, keyID)
	}

	return csrCmd
}
