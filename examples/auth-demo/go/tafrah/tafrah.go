package tafrah

/*
#cgo pkg-config: tafrah
#include <stdlib.h>
#include <tafrah/tafrah.h>
*/
import "C"

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"unsafe"
)

type ProofResult struct {
	Language                           string `json:"language"`
	NativeVersion                      string `json:"native_version"`
	MLKEM768SharedSecretMatch          bool   `json:"ml_kem_768_shared_secret_match"`
	MLKEM768TruncatedCTRejected        bool   `json:"ml_kem_768_truncated_ct_rejected"`
	SymmetricRoundtripOK               bool   `json:"symmetric_roundtrip_ok"`
	HashSHA256OK                       bool   `json:"hash_sha256_ok"`
	HQC128SharedSecretMatch            bool   `json:"hqc_128_shared_secret_match"`
	HQC128TruncatedCTRejected          bool   `json:"hqc_128_truncated_ct_rejected"`
	MLDSA65VerifyOK                    bool   `json:"ml_dsa_65_verify_ok"`
	MLDSA65TamperRejected              bool   `json:"ml_dsa_65_tamper_rejected"`
	MLDSA65TruncatedSigReject          bool   `json:"ml_dsa_65_truncated_sig_rejected"`
	SLHDSAShake128FVerifyOK            bool   `json:"slh_dsa_shake_128f_verify_ok"`
	SLHDSAShake128FPrehashOK           bool   `json:"slh_dsa_shake_128f_prehash_verify_ok"`
	SLHDSAShake128FPrehashTamperReject bool   `json:"slh_dsa_shake_128f_prehash_tamper_rejected"`
	SLHDSAShake128FTamperReject        bool   `json:"slh_dsa_shake_128f_tamper_rejected"`
	SLHDSAShake128FTruncReject         bool   `json:"slh_dsa_shake_128f_truncated_sig_rejected"`
	Falcon512VerifyOK                  bool   `json:"falcon_512_verify_ok"`
	Falcon512TamperRejected            bool   `json:"falcon_512_tamper_rejected"`
	Falcon512TruncatedRejected         bool   `json:"falcon_512_truncated_sig_rejected"`
	OverallOK                          bool   `json:"overall_ok"`
}

func statusText(status C.int) string {
	return C.GoString(C.tafrah_status_string(status))
}

func check(status C.int, op string) error {
	if status != C.TAFRAH_STATUS_OK {
		return fmt.Errorf("%s: %s", op, statusText(status))
	}
	return nil
}

func verify(status C.int, op string) (bool, error) {
	if status == C.TAFRAH_STATUS_OK {
		return true, nil
	}
	if status == C.TAFRAH_STATUS_VERIFICATION_FAILED {
		return false, nil
	}
	return false, fmt.Errorf("%s: %s", op, statusText(status))
}

func expectStatus(status C.int, expected C.int, op string) (bool, error) {
	if status == expected {
		return true, nil
	}
	return false, fmt.Errorf("%s: expected %s, got %s", op, statusText(expected), statusText(status))
}

func asPtr(buf []byte) *C.uint8_t {
	if len(buf) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&buf[0]))
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

func zeroBytes(buf []byte) {
	clear(buf)
}

func encodeParts(parts ...[]byte) []byte {
	out := make([]byte, 0)
	for _, part := range parts {
		size := uint32(len(part))
		out = append(out, byte(size>>24), byte(size>>16), byte(size>>8), byte(size))
		out = append(out, part...)
	}
	return out
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	prk := hmacSHA256(salt, ikm)
	okm := make([]byte, 0, length)
	block := []byte{}
	for counter := byte(1); len(okm) < length; counter++ {
		data := append(append(append([]byte{}, block...), info...), counter)
		block = hmacSHA256(prk, data)
		take := len(block)
		if take > length-len(okm) {
			take = length - len(okm)
		}
		okm = append(okm, block[:take]...)
	}
	return okm
}

func streamXOR(key, nonce, label, data []byte) []byte {
	stream := hkdfSHA256(
		key,
		[]byte("tafrah-auth-demo::stream-salt"),
		encodeParts([]byte("tafrah-auth-demo::stream"), label, nonce),
		len(data),
	)
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ stream[i]
	}
	return out
}

func RunProof() (ProofResult, error) {
	kemEk := make([]byte, int(C.tafrah_ml_kem_768_ek_size()))
	kemDk := make([]byte, int(C.tafrah_ml_kem_768_dk_size()))
	kemCt := make([]byte, int(C.tafrah_ml_kem_768_ct_size()))
	kemClientSS := make([]byte, int(C.tafrah_shared_secret_size()))
	kemServerSS := make([]byte, int(C.tafrah_shared_secret_size()))
	defer zeroBytes(kemDk)
	defer zeroBytes(kemClientSS)
	defer zeroBytes(kemServerSS)
	if err := check(C.tafrah_ml_kem_768_keygen(asPtr(kemEk), C.size_t(len(kemEk)), asPtr(kemDk), C.size_t(len(kemDk))), "tafrah_ml_kem_768_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_kem_768_encapsulate(asPtr(kemEk), C.size_t(len(kemEk)), asPtr(kemCt), C.size_t(len(kemCt)), asPtr(kemClientSS), C.size_t(len(kemClientSS))), "tafrah_ml_kem_768_encapsulate"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_kem_768_decapsulate(asPtr(kemDk), C.size_t(len(kemDk)), asPtr(kemCt), C.size_t(len(kemCt)), asPtr(kemServerSS), C.size_t(len(kemServerSS))), "tafrah_ml_kem_768_decapsulate"); err != nil {
		return ProofResult{}, err
	}
	kemTruncated, err := expectStatus(
		C.tafrah_ml_kem_768_decapsulate(asPtr(kemDk), C.size_t(len(kemDk)), asPtr(kemCt[:len(kemCt)-1]), C.size_t(len(kemCt)-1), asPtr(kemServerSS), C.size_t(len(kemServerSS))),
		C.TAFRAH_STATUS_INVALID_LENGTH,
		"tafrah_ml_kem_768_decapsulate_truncated",
	)
	if err != nil {
		return ProofResult{}, err
	}
	transportMaterial := hkdfSHA256(
		kemClientSS,
		[]byte("tafrah-auth-demo::transport-salt"),
		encodeParts([]byte("tafrah-auth-demo::transport")),
		64,
	)
	encKey := transportMaterial[:32]
	nonceSeed := sha256.Sum256(append(append([]byte{}, kemClientSS...), []byte("tafrah-auth-demo::nonce")...))
	nonce := append([]byte{}, nonceSeed[:16]...)
	plaintext := []byte("tafrah-auth-demo::symmetric-roundtrip")
	ciphertext := streamXOR(encKey, nonce, []byte("client->server"), plaintext)
	recovered := streamXOR(encKey, nonce, []byte("client->server"), ciphertext)
	hashInput := []byte("tafrah-auth-demo::hash::sha256")
	hashDigest := sha256.Sum256(hashInput)

	hqcEk := make([]byte, int(C.tafrah_hqc_128_ek_size()))
	hqcDk := make([]byte, int(C.tafrah_hqc_128_dk_size()))
	hqcCt := make([]byte, int(C.tafrah_hqc_128_ct_size()))
	hqcClientSS := make([]byte, int(C.tafrah_hqc_128_ss_size()))
	hqcServerSS := make([]byte, int(C.tafrah_hqc_128_ss_size()))
	defer zeroBytes(hqcDk)
	defer zeroBytes(hqcClientSS)
	defer zeroBytes(hqcServerSS)
	if err := check(C.tafrah_hqc_128_keygen(asPtr(hqcEk), C.size_t(len(hqcEk)), asPtr(hqcDk), C.size_t(len(hqcDk))), "tafrah_hqc_128_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_hqc_128_encapsulate(asPtr(hqcEk), C.size_t(len(hqcEk)), asPtr(hqcCt), C.size_t(len(hqcCt)), asPtr(hqcClientSS), C.size_t(len(hqcClientSS))), "tafrah_hqc_128_encapsulate"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_hqc_128_decapsulate(asPtr(hqcDk), C.size_t(len(hqcDk)), asPtr(hqcCt), C.size_t(len(hqcCt)), asPtr(hqcServerSS), C.size_t(len(hqcServerSS))), "tafrah_hqc_128_decapsulate"); err != nil {
		return ProofResult{}, err
	}
	hqcTruncated, err := expectStatus(
		C.tafrah_hqc_128_decapsulate(asPtr(hqcDk), C.size_t(len(hqcDk)), asPtr(hqcCt[:len(hqcCt)-1]), C.size_t(len(hqcCt)-1), asPtr(hqcServerSS), C.size_t(len(hqcServerSS))),
		C.TAFRAH_STATUS_INVALID_LENGTH,
		"tafrah_hqc_128_decapsulate_truncated",
	)
	if err != nil {
		return ProofResult{}, err
	}

	mlMsg := []byte("tafrah-auth-demo::ml-dsa-65")
	mlTampered := append(append([]byte{}, mlMsg...), 1)
	mlVk := make([]byte, int(C.tafrah_ml_dsa_65_vk_size()))
	mlSk := make([]byte, int(C.tafrah_ml_dsa_65_sk_size()))
	mlSig := make([]byte, int(C.tafrah_ml_dsa_65_sig_size()))
	defer zeroBytes(mlSk)
	if err := check(C.tafrah_ml_dsa_65_keygen(asPtr(mlVk), C.size_t(len(mlVk)), asPtr(mlSk), C.size_t(len(mlSk))), "tafrah_ml_dsa_65_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_dsa_65_sign(asPtr(mlSk), C.size_t(len(mlSk)), asPtr(mlMsg), C.size_t(len(mlMsg)), asPtr(mlSig), C.size_t(len(mlSig))), "tafrah_ml_dsa_65_sign"); err != nil {
		return ProofResult{}, err
	}
	mlTruncated, err := expectStatus(
		C.tafrah_ml_dsa_65_verify(asPtr(mlVk), C.size_t(len(mlVk)), asPtr(mlMsg), C.size_t(len(mlMsg)), asPtr(mlSig[:len(mlSig)-1]), C.size_t(len(mlSig)-1)),
		C.TAFRAH_STATUS_INVALID_LENGTH,
		"tafrah_ml_dsa_65_verify_truncated_sig",
	)
	if err != nil {
		return ProofResult{}, err
	}

	slhMsg := []byte("tafrah-auth-demo::slh-dsa-shake-128f")
	slhTampered := append(append([]byte{}, slhMsg...), 2)
	slhPrehashTampered := append(append([]byte{}, slhMsg...), 4)
	slhVk := make([]byte, int(C.tafrah_slh_dsa_shake_128f_vk_size()))
	slhSk := make([]byte, int(C.tafrah_slh_dsa_shake_128f_sk_size()))
	slhSig := make([]byte, int(C.tafrah_slh_dsa_shake_128f_sig_size()))
	slhPrehashSig := make([]byte, int(C.tafrah_slh_dsa_shake_128f_sig_size()))
	defer zeroBytes(slhSk)
	if err := check(C.tafrah_slh_dsa_shake_128f_keygen(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhSk), C.size_t(len(slhSk))), "tafrah_slh_dsa_shake_128f_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_slh_dsa_shake_128f_sign(asPtr(slhSk), C.size_t(len(slhSk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhSig), C.size_t(len(slhSig))), "tafrah_slh_dsa_shake_128f_sign"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_slh_dsa_shake_128f_hash_sha2_256_sign(asPtr(slhSk), C.size_t(len(slhSk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhPrehashSig), C.size_t(len(slhPrehashSig))), "tafrah_slh_dsa_shake_128f_hash_sha2_256_sign"); err != nil {
		return ProofResult{}, err
	}
	slhTruncated, err := expectStatus(
		C.tafrah_slh_dsa_shake_128f_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhSig[:len(slhSig)-1]), C.size_t(len(slhSig)-1)),
		C.TAFRAH_STATUS_INVALID_LENGTH,
		"tafrah_slh_dsa_shake_128f_verify_truncated_sig",
	)
	if err != nil {
		return ProofResult{}, err
	}

	falconMsg := []byte("tafrah-auth-demo::falcon-512")
	falconTampered := append(append([]byte{}, falconMsg...), 3)
	falconVk := make([]byte, int(C.tafrah_falcon_512_vk_size()))
	falconSk := make([]byte, int(C.tafrah_falcon_512_sk_size()))
	falconSig := make([]byte, int(C.tafrah_falcon_512_sig_size()))
	defer zeroBytes(falconSk)
	var falconSigWritten C.size_t
	if err := check(C.tafrah_falcon_512_keygen(asPtr(falconVk), C.size_t(len(falconVk)), asPtr(falconSk), C.size_t(len(falconSk))), "tafrah_falcon_512_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_falcon_512_sign(asPtr(falconSk), C.size_t(len(falconSk)), asPtr(falconMsg), C.size_t(len(falconMsg)), asPtr(falconSig), C.size_t(len(falconSig)), &falconSigWritten), "tafrah_falcon_512_sign"); err != nil {
		return ProofResult{}, err
	}
	falconSig = falconSig[:int(falconSigWritten)]
	falconTruncated, err := expectStatus(
		C.tafrah_falcon_512_verify(asPtr(falconVk), C.size_t(len(falconVk)), asPtr(falconMsg), C.size_t(len(falconMsg)), asPtr(falconSig[:len(falconSig)-1]), C.size_t(len(falconSig)-1)),
		C.TAFRAH_STATUS_INVALID_LENGTH,
		"tafrah_falcon_512_verify_truncated_sig",
	)
	if err != nil {
		return ProofResult{}, err
	}

	mlVerifyOK, err := verify(C.tafrah_ml_dsa_65_verify(asPtr(mlVk), C.size_t(len(mlVk)), asPtr(mlMsg), C.size_t(len(mlMsg)), asPtr(mlSig), C.size_t(len(mlSig))), "tafrah_ml_dsa_65_verify")
	if err != nil {
		return ProofResult{}, err
	}
	mlTamperRejected, err := verify(C.tafrah_ml_dsa_65_verify(asPtr(mlVk), C.size_t(len(mlVk)), asPtr(mlTampered), C.size_t(len(mlTampered)), asPtr(mlSig), C.size_t(len(mlSig))), "tafrah_ml_dsa_65_verify_tampered")
	if err != nil {
		return ProofResult{}, err
	}
	slhVerifyOK, err := verify(C.tafrah_slh_dsa_shake_128f_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhSig), C.size_t(len(slhSig))), "tafrah_slh_dsa_shake_128f_verify")
	if err != nil {
		return ProofResult{}, err
	}
	slhPrehashVerifyOK, err := verify(C.tafrah_slh_dsa_shake_128f_hash_sha2_256_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhPrehashSig), C.size_t(len(slhPrehashSig))), "tafrah_slh_dsa_shake_128f_hash_sha2_256_verify")
	if err != nil {
		return ProofResult{}, err
	}
	slhTamperRejected, err := verify(C.tafrah_slh_dsa_shake_128f_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhTampered), C.size_t(len(slhTampered)), asPtr(slhSig), C.size_t(len(slhSig))), "tafrah_slh_dsa_shake_128f_verify_tampered")
	if err != nil {
		return ProofResult{}, err
	}
	slhPrehashTamperRejected, err := verify(C.tafrah_slh_dsa_shake_128f_hash_sha2_256_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhPrehashTampered), C.size_t(len(slhPrehashTampered)), asPtr(slhPrehashSig), C.size_t(len(slhPrehashSig))), "tafrah_slh_dsa_shake_128f_hash_sha2_256_verify_tampered")
	if err != nil {
		return ProofResult{}, err
	}
	falconVerifyOK, err := verify(C.tafrah_falcon_512_verify(asPtr(falconVk), C.size_t(len(falconVk)), asPtr(falconMsg), C.size_t(len(falconMsg)), asPtr(falconSig), C.size_t(len(falconSig))), "tafrah_falcon_512_verify")
	if err != nil {
		return ProofResult{}, err
	}
	falconTamperRejected, err := verify(C.tafrah_falcon_512_verify(asPtr(falconVk), C.size_t(len(falconVk)), asPtr(falconTampered), C.size_t(len(falconTampered)), asPtr(falconSig), C.size_t(len(falconSig))), "tafrah_falcon_512_verify_tampered")
	if err != nil {
		return ProofResult{}, err
	}

	out := ProofResult{
		Language:                           "go",
		NativeVersion:                      C.GoString(C.tafrah_version()),
		MLKEM768SharedSecretMatch:          constantTimeEqual(kemClientSS, kemServerSS),
		MLKEM768TruncatedCTRejected:        kemTruncated,
		SymmetricRoundtripOK:               constantTimeEqual(plaintext, recovered),
		HashSHA256OK:                       fmt.Sprintf("%x", hashDigest[:]) == "5f36ca6b07d4d4a0162b71332eddefb1b79719d4719e09e2e880c059881ef00b",
		HQC128SharedSecretMatch:            constantTimeEqual(hqcClientSS, hqcServerSS),
		HQC128TruncatedCTRejected:          hqcTruncated,
		MLDSA65VerifyOK:                    mlVerifyOK,
		MLDSA65TamperRejected:              !mlTamperRejected,
		MLDSA65TruncatedSigReject:          mlTruncated,
		SLHDSAShake128FVerifyOK:            slhVerifyOK,
		SLHDSAShake128FPrehashOK:           slhPrehashVerifyOK,
		SLHDSAShake128FPrehashTamperReject: !slhPrehashTamperRejected,
		SLHDSAShake128FTamperReject:        !slhTamperRejected,
		SLHDSAShake128FTruncReject:         slhTruncated,
		Falcon512VerifyOK:                  falconVerifyOK,
		Falcon512TamperRejected:            !falconTamperRejected,
		Falcon512TruncatedRejected:         falconTruncated,
	}
	out.OverallOK = out.MLKEM768SharedSecretMatch &&
		out.MLKEM768TruncatedCTRejected &&
		out.SymmetricRoundtripOK &&
		out.HashSHA256OK &&
		out.HQC128SharedSecretMatch &&
		out.HQC128TruncatedCTRejected &&
		out.MLDSA65VerifyOK &&
		out.MLDSA65TamperRejected &&
		out.MLDSA65TruncatedSigReject &&
		out.SLHDSAShake128FVerifyOK &&
		out.SLHDSAShake128FPrehashOK &&
		out.SLHDSAShake128FPrehashTamperReject &&
		out.SLHDSAShake128FTamperReject &&
		out.SLHDSAShake128FTruncReject &&
		out.Falcon512VerifyOK &&
		out.Falcon512TamperRejected &&
		out.Falcon512TruncatedRejected
	return out, nil
}

func RunProofJSON() (string, error) {
	out, err := RunProof()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}
