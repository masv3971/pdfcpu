package api

import (
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/pkg/errors"
)

var (
	ErrHasAcroForm = errors.New("pdfcpu: existing")

	ErrImposibleByteRangeValue = errors.New("Impossible byteRange value")
)

type Signer interface {
	EstimateSignatureLength() int
	Sign(data io.Reader) ([]byte, error)
}

// SignFile signs inFile with a digital signature and writes the result to outFile.
func SignFile(inFile, outFile string, conf *model.Configuration, signer Signer) (err error) {
	if conf == nil {
		conf = model.NewDefaultConfiguration()
	}

	ctx, err := ReadContextFile(inFile)

	if err != nil {
		return err
	}
	// Write to outFile
	ctx.Write.DirName = "."
	ctx.Write.FileName = outFile
	if err := pdfcpu.Write(ctx); err != nil {
		return err
	}

	//if err := PrepareSignature(ctx, signer); err != nil {
	//	return err
	//}

	//if err := Sign(ctx, outFile, signer); err != nil {
	//	return err
	//}
	return nil
}

// SignFile signs inFile with a digital signature and writes the result to outFile.
func TimestampFile(inFile, outFile string, cert *x509.Certificate, pKey crypto.PrivateKey, conf *model.Configuration, signer Signer) (err error) {
	if conf == nil {
		conf = model.NewDefaultConfiguration()
	}

	f, err := os.Open(inFile)
	if err != nil {
		return err
	}

	ctx, _, _, _, err := readValidateAndOptimize(f, conf, time.Now())
	if err != nil {
		return err
	}

	if err := PrepareTimestamp(ctx, signer); err != nil {
		return err
	}

	if err := Sign(ctx, outFile, signer); err != nil {
		return err
	}
	return nil
}
func PrepareSignature(ctx *model.Context, signer Signer) error {
	// hack
	ctx.Configuration.WriteObjectStream = false

	xRefTable := ctx.XRefTable

	rootDict, err := xRefTable.Catalog()
	if err != nil {
		return err
	}

	if _, found := rootDict.Find("AcroForm"); found {
		return ErrHasAcroForm
	}

	maxSigContentBytes := signer.EstimateSignatureLength()

	// Create Sig dict:
	sigDict := types.Dict(
		map[string]types.Object{
			"Type":      types.Name("Sig"),
			"Filter":    types.Name("Adobe.PPKLite"),
			"SubFilter": types.Name("adbe.pkcs7.detached"),
			"Contents":  types.NewHexLiteral(make([]byte, maxSigContentBytes)),
			"ByteRange": types.NewNumberArray(0, 0, 0, 0),
			"M":         types.StringLiteral(types.DateString(time.Now())),
		},
	)

	ir, err := xRefTable.IndRefForNewObject(sigDict)
	if err != nil {
		return err
	}

	// Create Acrofield
	sigFieldDict := types.Dict(
		map[string]types.Object{
			"Type":    types.Name("Annot"),
			"Subtype": types.Name("Widget"),
			"FT":      types.Name("Sig"),
			"T":       types.StringLiteral("Signature"),
			"Rect":    types.NewNumberArray(0, 0, 0, 0),
			"V":       *ir,
		},
	)

	ir, err = xRefTable.IndRefForNewObject(sigFieldDict)
	if err != nil {
		return err
	}

	// Link 1st page to Signature Field dictionary, otherwise signature is not visible. check specs...
	pages, err := xRefTable.DereferenceDictEntry(xRefTable.RootDict, "Pages")
	if err != nil {
		return err
	}
	kids := pages.(types.Dict).ArrayEntry("Kids")
	page0, err := xRefTable.DereferenceDict(kids[0])
	if err != nil {
		return err
	}
	annots := types.Array{*ir}
	page0.Update("Annots", annots)

	// Create AcroForm
	acroForm := types.Dict(
		map[string]types.Object{
			"Fields":   types.Array{*ir},
			"SigFlags": types.Integer(3),
		},
	)

	if ir, err = xRefTable.IndRefForNewObject(acroForm); err != nil {
		return err
	}

	if ok := rootDict.Insert("AcroForm", *ir); !ok {
		return errors.New("Not OK insert of AcroForm")
	}

	return nil
}

func PrepareTimestamp(ctx *model.Context, signer Signer) error {
	// hack
	ctx.Configuration.WriteObjectStream = false

	xRefTable := ctx.XRefTable

	rootDict, err := xRefTable.Catalog()
	if err != nil {
		return err
	}

	if _, found := rootDict.Find("AcroForm"); found {
		return ErrHasAcroForm
	}

	maxSigContentBytes := signer.EstimateSignatureLength()

	// Create Sig dict:
	sigDict := types.Dict(
		map[string]types.Object{
			"Type":      types.Name("DocTimeStamp"),
			"Filter":    types.Name("Adobe.PPKLite"),
			"SubFilter": types.Name("ETSI.RFC3161"),
			"Contents":  types.NewHexLiteral(make([]byte, maxSigContentBytes)),
			"ByteRange": types.Array{},
		},
	)

	ir, err := xRefTable.IndRefForNewObject(sigDict)
	if err != nil {
		return err
	}

	// Create Acrofield
	sigFieldDict := types.Dict(
		map[string]types.Object{
			"Type":    types.Name("Annot"),
			"Subtype": types.Name("Widget"),
			"FT":      types.Name("Sig"),
			"T":       types.StringLiteral("Signature"),
			"Rect":    types.Array{},
			"V":       *ir,
		},
	)

	if ir, err = xRefTable.IndRefForNewObject(sigFieldDict); err != nil {
		return err
	}

	// Link 1st page to Signature Field dictionary, otherwise signature is not visible. check specs...
	pg, _ := xRefTable.DereferenceDictEntry(xRefTable.RootDict, "Pages")
	pgd := pg.(types.Dict)
	kids := pgd.ArrayEntry("Kids")
	p0, _ := xRefTable.DereferenceDict(kids[0])

	annots := types.Array{*ir}
	p0.Update("Annots", annots)

	// Create AcroForm
	formDict := types.Dict(
		map[string]types.Object{
			"Fields":   types.Array{*ir},
			"SigFlags": types.Integer(3),
		},
	)

	if ir, err = xRefTable.IndRefForNewObject(formDict); err != nil {
		return err
	}

	rootDict.Insert("AcroForm", *ir)

	return nil
}

// Sign creates a digital signature for xRefTable and writes the result to outFile.
func Sign(ctx *model.Context, outFile string, signer Signer) error {
	// hack
	ctx.Configuration.WriteObjectStream = false

	maxSigContentBytes := signer.EstimateSignatureLength()

	// Write to outFile
	ctx.Write.DirName = "."
	ctx.Write.FileName = outFile
	if err := pdfcpu.Write(ctx); err != nil {
		return err
	}
	// Read hashed part of file
	f, err := os.OpenFile(outFile, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	i, err := f.Stat()
	if err != nil {
		return err
	}
	ctx.Write.FileSize = int64(i.Size())
	fmt.Println("fileSize", ctx.Write.FileSize)

	posBeforeSig := 0
	lenBeforeSig := ctx.Write.OffsetSigContents - int64(posBeforeSig)

	posAfterSig := ctx.Write.OffsetSigContents + 2 + int64(maxSigContentBytes)
	lenAfterSig := ctx.Write.FileSize - int64(posAfterSig)

	//if ctx.Write.FileSize < posAfterSig {
	//	return ErrImposibleByteRangeValue
	//}

	//if (brStartOfFile + int(brStartOfSignatureContent) + int(brEndOfSignatureContent) + int(brFromSignatureContentToEOF)) > int(ctx.Write.FileSize) {
	//	return ErrImposibleByteRangeValue
	//}

	byteArray := types.NewIntegerArray(
		posBeforeSig,
		int(lenBeforeSig),
		int(posAfterSig),
		int(lenAfterSig),
	)

	fmt.Println("byteRange", byteArray.PDFString())

	// Patch "ByteArray" in signature dict.
	if err := patchFile(outFile, []byte(byteArray.PDFString()), ctx.Write.OffsetSigByteRange); err != nil {
		return err
	}

	part0 := io.NewSectionReader(f, int64(posBeforeSig), int64(lenBeforeSig))
	part1 := io.NewSectionReader(f, int64(posAfterSig), int64(lenAfterSig))

	pdfReader := io.MultiReader(part0, part1)

	// Create signature(outFile, byteRanges)
	sig, err := signer.Sign(pdfReader)
	if err != nil {
		return err
	}
	content := []byte(hex.EncodeToString(sig))

	fmt.Println("Offset content", ctx.Write.OffsetSigContents+1)

	// Patch "Contents" in signature dict.
	if err := patchFile(outFile, content, ctx.Write.OffsetSigContents+1); err != nil {
		return err
	}
	return nil
}

func patchFile(outFileName string, bb []byte, offset int64) error {
	f, err := os.OpenFile(outFileName, os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return err
	}

	if _, err := f.WriteAt(bb, offset); err != nil {
		return err
	}

	return nil
}
