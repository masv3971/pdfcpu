package api

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"testing"

	"github.com/madflojo/testcerts"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/stretchr/testify/assert"
	"go.mozilla.org/pkcs7"
)

var estimateSignatureLength = 10000

type mockSigner struct {
	Signer
}

func (m mockSigner) Sign(r io.Reader) ([]byte, error) {
	cert, key := mockCertKey(&testing.T{})
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	hash := h.Sum(b)

	// Initialize a SignedData struct with content to be signed
	signedData, err := pkcs7.NewSignedData(hash)
	if err != nil {
		return nil, fmt.Errorf("Cannot initialize signed data: %s", err)
	}

	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// Add the signing cert and private key
	fmt.Println(reflect.TypeOf(key))
	if err := signedData.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		return nil, fmt.Errorf("Cannot add signer: %s", err)
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()

	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return nil, fmt.Errorf("Cannot finish signing data: %s", err)
	}

	//if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS7", Bytes: detachedSignature}); err != nil {
	//	return nil, err
	//}
	return detachedSignature, nil
}

func mockCertKey(t *testing.T) (*x509.Certificate, crypto.PrivateKey) {
	c, k, err := testcerts.GenerateCerts()
	assert.NoError(t, err)

	decodedCert, _ := pem.Decode(c)
	decodedKey, _ := pem.Decode(k)

	cert, err := x509.ParseCertificate(decodedCert.Bytes)
	key, err := x509.ParsePKCS1PrivateKey(decodedKey.Bytes)
	return cert, key
}

func (m mockSigner) EstimateSignatureLength() int {
	return estimateSignatureLength
}

func TestSign(t *testing.T) {
	tts := []struct {
		name    string
		inFile  string
		outFile string
	}{
		{
			name:    "OK",
			inFile:  "../testdata/go.pdf",
			outFile: "../testdata/go-sign.pdf",
		},
	}

	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			//cert, key := mockCertKey(t)
			signer := mockSigner{}
			err := SignFile(tt.inFile, tt.outFile, nil, signer)
			assert.NoError(t, err)
		})
	}
}

func TestPrepareSignature_root(t *testing.T) {
	tts := []struct {
		name string
		have string
		want types.Dict
	}{
		{
			name: "OK",
			have: "../testdata/go.pdf",
			want: types.Dict{
				"AcroForm": *types.NewIndirectRef(515, 0),
				"Lang":     types.StringLiteral("he-IL"),
				"MarkInfo": types.Dict{
					"Marked": types.Boolean(true),
				},
				"Pages":          *types.NewIndirectRef(2, 0),
				"StructTreeRoot": *types.NewIndirectRef(107, 0),
				"Type":           types.Name("Catalog"),
			},
		},
	}
	for _, tt := range tts {
		t.Run(tt.name, func(t *testing.T) {
			ctx, err := ReadContextFile(tt.have)
			estimateSignatureLength = 2
			assert.NoError(t, err)

			signer := mockSigner{}
			err = PrepareSignature(ctx, signer)
			assert.NoError(t, err)

			rootDict, err := ctx.XRefTable.Catalog()
			assert.NoError(t, err)
			assert.Equal(t, tt.want, rootDict)
		})
	}
}
