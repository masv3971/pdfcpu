package pdfcpu

import (
	"fmt"
	"strings"

	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/types"
	"github.com/pkg/errors"
)

func sigDictPDFString(d types.Dict) string {
	logstr := []string{}
	logstr = append(logstr, "<<")
	logstr = append(logstr, fmt.Sprintf("/ByteRange%-62v", d["ByteRange"].PDFString()))
	logstr = append(logstr, fmt.Sprintf("/Contents%s", d["Contents"].PDFString()))
	logstr = append(logstr, fmt.Sprintf("/Type%s", d["Type"].PDFString()))
	logstr = append(logstr, fmt.Sprintf("/Filter%s", d["Filter"].PDFString()))
	logstr = append(logstr, fmt.Sprintf("/SubFilter%s", d["SubFilter"].PDFString()))
	logstr = append(logstr, fmt.Sprintf("/M%s", d["M"].PDFString()))
	logstr = append(logstr, ">>")
	return strings.Join(logstr, "")
}

func writeSigDict(ctx *model.Context, ir types.IndirectRef) error {
	// 	<<
	// 		<ByteRange, []>
	// 		<Contents, <00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000>>
	// 		<Filter, Adobe.PPKLite>
	// 		<SubFilter, adbe.pkcs7.detached>
	// 		<Type, Sig>
	// >>

	d, err := ctx.DereferenceDict(ir)
	if err != nil {
		return err
	}

	if d.Type() == nil {
		return errors.New("sig dict: Type is nil")
	}

	filter := d.Filter()
	if filter == nil || *filter != "Adobe.PPKLite" {
		return errors.Errorf("sig dict: unexpected Filter: %s", *filter)
	}

	if d.SubFilter() == nil {
		return errors.New("sig dict: SubFilter is nil")
	}

	objNr := ir.ObjectNumber.Value()
	genNr := ir.GenerationNumber.Value()

	// Set write-offset for this object.
	w := ctx.Write
	w.SetWriteOffset(objNr)

	written, err := writeObjectHeader(w, objNr, genNr)
	if err != nil {
		return err
	}

	// /ByteRange[]
	w.OffsetSigByteRange = w.Offset + int64(written) + 2 + 10
	// 2 for "<<"
	// 10 for "/ByteRange"

	// /Contents<00..... maxSigContentsBytes>
	w.OffsetSigContents = w.OffsetSigByteRange + 1 + 60 + 1 + 9
	// 1 for "["
	// 60 for max 60 chars within this array PDF string.
	// 1 for "]"
	// 9 for "/Contents<"

	//fmt.Println("SigDict", sigDictPDFString(d))

	i, err := w.WriteString(sigDictPDFString(d))
	if err != nil {
		return err
	}
	//i := 20174

	j, err := writeObjectTrailer(w)
	if err != nil {
		return err
	}

	// Write-offset for next object.
	w.Offset += int64(written + i + j)

	// Record writeOffset for first and last char of Contents.

	// Record writeOffset for ByteArray...

	return nil
}

func writeSigFieldDict(ctx *model.Context, sigField types.Dict, objNr, genNr int) error {
	// 	<<
	// 		<DA, (/Courier 0 Tf)>
	// 		<FT, Sig>
	// 		<Rect, [0.00 0.00 0.00 0.00]>
	// 		<Subtype, Widget>
	// 		<T, (Signature)>
	// 		<Type, Annot>
	// 		<V, (21 0 R)>
	// >>

	if err := writeDictObject(ctx, objNr, genNr, sigField); err != nil {
		return err
	}

	ir := sigField.IndirectRefEntry("V")
	if ir == nil {
		return errors.New("sig field dict: missing V")
	}

	if err := writeSigDict(ctx, *ir); err != nil {
		return err
	}

	return nil
}

func writeSignature(ctx *model.Context, sig types.Dict, objNr, genNr int) error {
	// <<
	// 	<DR, <<
	// 		<Font, <<
	// 			<Courier, (19 0 R)>
	// 		>>>
	// 	>>>
	// 	<Fields, [(20 0 R)]>
	// 	<SigFlags, 3>
	// >>

	if err := writeDictObject(ctx, objNr, genNr, sig); err != nil {
		return err
	}
	/*
		// Write font resource
		resDict := d.DictEntry("DR")
		fontResDict := resDict.DictEntry("Font")
		ir := fontResDict.IndirectRefEntry("Courier")
		if _, err := writeIndirectObject(ctx, *ir); err != nil {
			return err
		}
	*/

	// Write fields
	fields := sig.ArrayEntry("Fields")
	if fields == nil {
		return errors.New("acroform dict: missing Fields")
	}
	for _, field := range fields {
		ir, ok := field.(types.IndirectRef)
		if !ok {
			return errors.New("acroform dict fields: expecting indRef")
		}
		d, err := ctx.DereferenceDict(ir)
		if err != nil {
			return err
		}
		ft := d.NameEntry("FT")
		if ft == nil || *ft != "Sig" {
			if _, err := writeIndirectObject(ctx, ir); err != nil {
				return err
			}
			continue
		}
		objNr := ir.ObjectNumber.Value()
		genNr := ir.GenerationNumber.Value()
		if err := writeSigFieldDict(ctx, d, objNr, genNr); err != nil {
			return err
		}
	}
	return nil
}
