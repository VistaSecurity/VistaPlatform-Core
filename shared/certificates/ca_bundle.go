package certificates

import (
	"crypto/sha256"
	"encoding/pem"
	"strings"
)

// MergeCAPEMs returns the union of two PEM bundles, keeping every certificate
// in `existing` and appending any from `incoming` that are not already present.
// Order is stable: existing certificates first, then genuinely new ones.
//
// Why agents need this rather than an assignment. An agent verifies the
// platform against an anchor the operator approved at setup (see
// ResolveTrustAnchor). Registration then hands back the platform's own agent CA
// in `server_ca_cert`, and the agents used to *replace* the approved anchor
// with it. That is only correct when the agent also moves to the mTLS
// passthrough listener, whose server certificate that CA actually issued — and
// the passthrough only exists when agentMtls is enabled, which is NOT the chart
// default. With it off, the agent stayed on the ordinary edge endpoint while
// trusting a CA that had not signed the edge certificate, so every call after
// registration failed the handshake: the sensor registered, then went silent.
//
// Keeping both is correct rather than merely lenient. Each CA is trusted on its
// own merits — the operator approved the first, and the second arrives over the
// connection the first just authenticated — and which endpoint the agent ends
// up talking to is a deployment choice it should not have to predict. Replacing
// throws away a decision a human made; a union does not.
//
// Malformed input is treated conservatively: if `incoming` contains no parsable
// certificate, `existing` is returned unchanged rather than being clobbered by
// something unusable. Losing a working anchor is the failure this exists to
// prevent, so it must not be reachable through bad input either.
func MergeCAPEMs(existing, incoming string) string {
	existingBlocks, existingSeen := decodeCertBlocks(existing)
	incomingBlocks, _ := decodeCertBlocks(incoming)

	if len(incomingBlocks) == 0 {
		return existing
	}
	if len(existingBlocks) == 0 {
		return encodeCertBlocks(incomingBlocks)
	}

	merged := existingBlocks
	for _, blk := range incomingBlocks {
		key := sha256.Sum256(blk.Bytes)
		if _, dup := existingSeen[key]; dup {
			continue
		}
		existingSeen[key] = struct{}{}
		merged = append(merged, blk)
	}
	return encodeCertBlocks(merged)
}

// decodeCertBlocks returns every CERTIFICATE block in a PEM bundle, plus a set
// of their content hashes for de-duplication. Non-certificate blocks (a key
// pasted into the wrong file, say) are dropped rather than carried into a trust
// bundle. De-duplication is by DER bytes, so the same certificate re-encoded
// with different line breaks or headers still counts as one.
func decodeCertBlocks(bundle string) ([]*pem.Block, map[[32]byte]struct{}) {
	var (
		blocks []*pem.Block
		seen   = make(map[[32]byte]struct{})
		rest   = []byte(strings.TrimSpace(bundle))
	)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		key := sha256.Sum256(blk.Bytes)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		blocks = append(blocks, &pem.Block{Type: blk.Type, Bytes: blk.Bytes})
	}
	return blocks, seen
}

func encodeCertBlocks(blocks []*pem.Block) string {
	var sb strings.Builder
	for _, blk := range blocks {
		// pem.EncodeToMemory only fails on a malformed block, and these came
		// from pem.Decode, so they are well-formed by construction.
		sb.Write(pem.EncodeToMemory(blk))
	}
	return sb.String()
}
