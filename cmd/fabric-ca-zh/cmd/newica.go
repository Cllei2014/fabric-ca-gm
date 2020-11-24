package cmd

import (
	"bufio"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"github.com/Hyperledger-TWGC/tjfoc-gm/sm2"
	"github.com/cloudflare/cfssl/config"
	cferr "github.com/cloudflare/cfssl/errors"
	kms "github.com/tw-bc-group/aliyun-kms/sm2"
	"io"
	"io/ioutil"
	"math/big"
	"os"
	"time"

	x509GM "github.com/Hyperledger-TWGC/tjfoc-gm/x509"
	"github.com/cloudflare/cfssl/csr"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/spf13/cobra"
)

//签发证书有效期参数
const oneYearHours = 8760

type subjectPublicKeyInfo struct {
	Algorithm        pkix.AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

func computeSKI(csrTemp *x509GM.CertificateRequest) ([]byte, error) {
	pubKey := csrTemp.PublicKey
	encodedPub, err := x509GM.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, err
	}

	var subPKI subjectPublicKeyInfo
	_, err = asn1.Unmarshal(encodedPub, &subPKI)
	if err != nil {
		return nil, err
	}

	pubHash := sha1.Sum(subPKI.SubjectPublicKey.Bytes)
	return pubHash[:], nil
}

func getParentCA(path string) (*x509GM.Certificate, error) {
	var reader io.Reader
	if path == "" {
		reader = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		reader = bufio.NewReader(file)
	}

	bytesRead, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return x509GM.ReadCertificateFromPem(bytesRead)
}

func newICATemplate(subj string, publicKey *sm2.PublicKey) (*x509GM.Certificate, error) {
	csrTemp, err := NewCsrTemplate(subj, publicKey)
	if err != nil {
		return nil, err
	}

	icaTemp := &x509GM.Certificate{
		Subject:            csrTemp.Subject,
		PublicKey:          csrTemp.PublicKey,
		PublicKeyAlgorithm: csrTemp.PublicKeyAlgorithm,
		SignatureAlgorithm: csrTemp.SignatureAlgorithm,
		//以下参数设置域名参数，目前忽略
		DNSNames:           csrTemp.DNSNames,
		IPAddresses:        csrTemp.IPAddresses,
		EmailAddresses:     csrTemp.EmailAddresses,
	}

	oneYear, err := time.ParseDuration(fmt.Sprintf("%dh", oneYearHours))
	if err != nil {
		return nil, err
	}

	icaTemp.NotBefore = time.Now()
	icaTemp.NotAfter = icaTemp.NotBefore.Add(oneYear)

	for _, extension := range csrTemp.Extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier(x509.OIDExtensionBasicConstraints)) {
			var constraints csr.BasicConstraints

			if _, err = asn1.Unmarshal(extension.Value, &constraints); err != nil {
				return nil, err
			}

			icaTemp.BasicConstraintsValid = true
			icaTemp.IsCA = constraints.IsCA
			icaTemp.MaxPathLen = constraints.MaxPathLen
			icaTemp.MaxPathLenZero = icaTemp.MaxPathLen == 0
		}
	}

	serialNumber := make([]byte, 20)
	_, err = io.ReadFull(rand.Reader, serialNumber)
	if err != nil {
		return nil, err
	}

	// make sure not negative
	serialNumber[0] &= 0x7F
	icaTemp.SerialNumber = new(big.Int).SetBytes(serialNumber)

	// construct key usage
	signingProfile := &config.SigningProfile{
		Usage: []string{"cert sign", "crl sign", "digital signature", "key encipherment"},
	}

	ku, eku, _ := signingProfile.Usages()
	if ku == 0 && len(eku) == 0 {
		return nil, cferr.New(cferr.PolicyError, cferr.NoKeyUsages)
	}

	sm2eku := make([]x509GM.ExtKeyUsage, len(eku))
	for i := 0; i < len(eku); i++ {
		sm2eku[i] = x509GM.ExtKeyUsage(eku[i])
	}

	icaTemp.KeyUsage = x509GM.KeyUsage(ku)
	icaTemp.ExtKeyUsage = sm2eku

	ski, err := computeSKI(csrTemp)
	if err != nil {
		return nil, err
	}

	icaTemp.SubjectKeyId = ski

	return icaTemp, nil
}

func newICA(subj, parentCAPath, parentKeyID, keyID string) error {
	parentCA, err := getParentCA(parentCAPath)
	if err != nil {
		return err
	}

	keyAdapter, err := kms.CreateSm2KeyAdapter(keyID, kms.SignAndVerify)
	if err != nil {
		return err
	}

	publicKey, err := keyAdapter.GetPublicKey()
	if err != nil {
		return err
	}

	icaTemp, err := newICATemplate(subj, publicKey)
	if err != nil {
		return err
	}

	parentKeyAdapter, err := kms.CreateSm2KeyAdapter(parentKeyID, kms.SignAndVerify)
	if err != nil {
		return err
	}

	signer, err := parentKeyAdapter.TryIntoCryptoSigner()
	if err != nil {
		return err
	}

	certPem, err := x509GM.CreateCertificateToPem(icaTemp, parentCA, publicKey, signer)
	if err != nil {
		return err
	}

	printOutput(keyAdapter.KeyID(), string(certPem))
	return nil
}

func NewICACmd() *cobra.Command {
	var subj, parentCAPath, keyID, parentKeyID string

	caCmd := &cobra.Command{
		Use:   "newica",
		Short: "Generate a new ica",
		Long:  "Generate a new intermediary certificate authority with a given ca file",
	}

	caCmd.Flags().StringVarP(&subj, "subj", "s", "", "设置新证书的 Subject 字段（必选）")
	_ = caCmd.MarkFlagRequired("subj")

	caCmd.Flags().StringVarP(&parentCAPath, "ca", "c", "", "设置新证书的上级 CA 证书文件路径（必选）")
	_ = caCmd.MarkFlagRequired("ca")

	caCmd.Flags().StringVarP(&parentKeyID, "pkey", "p", "", "设置新证书的上级 CA 私钥（必选）")
	_ = caCmd.MarkFlagRequired("pkey")

	caCmd.Flags().StringVarP(&keyID, "key", "k", "", "设置新证书的私钥（可选）")

	caCmd.RunE = func(cmd *cobra.Command, args []string) error {
		return newICA(subj, parentCAPath, parentKeyID, keyID)
	}

	return caCmd
}
