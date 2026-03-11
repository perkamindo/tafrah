package tafrah

/*
#cgo pkg-config: tafrah
#include <stdlib.h>
#include <tafrah/tafrah.h>
*/
import "C"

import (
	"encoding/json"
	"fmt"
	"unsafe"
)

type ProofResult struct {
	Language                    string `json:"language"`
	NativeVersion               string `json:"native_version"`
	MLKEM768SharedSecretMatch   bool   `json:"ml_kem_768_shared_secret_match"`
	HQC128SharedSecretMatch     bool   `json:"hqc_128_shared_secret_match"`
	MLDSA65VerifyOK             bool   `json:"ml_dsa_65_verify_ok"`
	MLDSA65TamperRejected       bool   `json:"ml_dsa_65_tamper_rejected"`
	SLHDSAShake128FVerifyOK     bool   `json:"slh_dsa_shake_128f_verify_ok"`
	SLHDSAShake128FTamperReject bool   `json:"slh_dsa_shake_128f_tamper_rejected"`
	Falcon512VerifyOK           bool   `json:"falcon_512_verify_ok"`
	Falcon512TamperRejected     bool   `json:"falcon_512_tamper_rejected"`
	OverallOK                   bool   `json:"overall_ok"`
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

func asPtr(buf []byte) *C.uint8_t {
	if len(buf) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&buf[0]))
}

func RunProof() (ProofResult, error) {
	kemEk := make([]byte, int(C.tafrah_ml_kem_768_ek_size()))
	kemDk := make([]byte, int(C.tafrah_ml_kem_768_dk_size()))
	kemCt := make([]byte, int(C.tafrah_ml_kem_768_ct_size()))
	kemClientSS := make([]byte, int(C.tafrah_shared_secret_size()))
	kemServerSS := make([]byte, int(C.tafrah_shared_secret_size()))
	if err := check(C.tafrah_ml_kem_768_keygen(asPtr(kemEk), C.size_t(len(kemEk)), asPtr(kemDk), C.size_t(len(kemDk))), "tafrah_ml_kem_768_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_kem_768_encapsulate(asPtr(kemEk), C.size_t(len(kemEk)), asPtr(kemCt), C.size_t(len(kemCt)), asPtr(kemClientSS), C.size_t(len(kemClientSS))), "tafrah_ml_kem_768_encapsulate"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_kem_768_decapsulate(asPtr(kemDk), C.size_t(len(kemDk)), asPtr(kemCt), C.size_t(len(kemCt)), asPtr(kemServerSS), C.size_t(len(kemServerSS))), "tafrah_ml_kem_768_decapsulate"); err != nil {
		return ProofResult{}, err
	}

	hqcEk := make([]byte, int(C.tafrah_hqc_128_ek_size()))
	hqcDk := make([]byte, int(C.tafrah_hqc_128_dk_size()))
	hqcCt := make([]byte, int(C.tafrah_hqc_128_ct_size()))
	hqcClientSS := make([]byte, int(C.tafrah_hqc_128_ss_size()))
	hqcServerSS := make([]byte, int(C.tafrah_hqc_128_ss_size()))
	if err := check(C.tafrah_hqc_128_keygen(asPtr(hqcEk), C.size_t(len(hqcEk)), asPtr(hqcDk), C.size_t(len(hqcDk))), "tafrah_hqc_128_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_hqc_128_encapsulate(asPtr(hqcEk), C.size_t(len(hqcEk)), asPtr(hqcCt), C.size_t(len(hqcCt)), asPtr(hqcClientSS), C.size_t(len(hqcClientSS))), "tafrah_hqc_128_encapsulate"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_hqc_128_decapsulate(asPtr(hqcDk), C.size_t(len(hqcDk)), asPtr(hqcCt), C.size_t(len(hqcCt)), asPtr(hqcServerSS), C.size_t(len(hqcServerSS))), "tafrah_hqc_128_decapsulate"); err != nil {
		return ProofResult{}, err
	}

	mlMsg := []byte("tafrah-auth-demo::ml-dsa-65")
	mlTampered := append(append([]byte{}, mlMsg...), 1)
	mlVk := make([]byte, int(C.tafrah_ml_dsa_65_vk_size()))
	mlSk := make([]byte, int(C.tafrah_ml_dsa_65_sk_size()))
	mlSig := make([]byte, int(C.tafrah_ml_dsa_65_sig_size()))
	if err := check(C.tafrah_ml_dsa_65_keygen(asPtr(mlVk), C.size_t(len(mlVk)), asPtr(mlSk), C.size_t(len(mlSk))), "tafrah_ml_dsa_65_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_ml_dsa_65_sign(asPtr(mlSk), C.size_t(len(mlSk)), asPtr(mlMsg), C.size_t(len(mlMsg)), asPtr(mlSig), C.size_t(len(mlSig))), "tafrah_ml_dsa_65_sign"); err != nil {
		return ProofResult{}, err
	}

	slhMsg := []byte("tafrah-auth-demo::slh-dsa-shake-128f")
	slhTampered := append(append([]byte{}, slhMsg...), 2)
	slhVk := make([]byte, int(C.tafrah_slh_dsa_shake_128f_vk_size()))
	slhSk := make([]byte, int(C.tafrah_slh_dsa_shake_128f_sk_size()))
	slhSig := make([]byte, int(C.tafrah_slh_dsa_shake_128f_sig_size()))
	if err := check(C.tafrah_slh_dsa_shake_128f_keygen(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhSk), C.size_t(len(slhSk))), "tafrah_slh_dsa_shake_128f_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_slh_dsa_shake_128f_sign(asPtr(slhSk), C.size_t(len(slhSk)), asPtr(slhMsg), C.size_t(len(slhMsg)), asPtr(slhSig), C.size_t(len(slhSig))), "tafrah_slh_dsa_shake_128f_sign"); err != nil {
		return ProofResult{}, err
	}

	falconMsg := []byte("tafrah-auth-demo::falcon-512")
	falconTampered := append(append([]byte{}, falconMsg...), 3)
	falconVk := make([]byte, int(C.tafrah_falcon_512_vk_size()))
	falconSk := make([]byte, int(C.tafrah_falcon_512_sk_size()))
	falconSig := make([]byte, int(C.tafrah_falcon_512_sig_size()))
	var falconSigWritten C.size_t
	if err := check(C.tafrah_falcon_512_keygen(asPtr(falconVk), C.size_t(len(falconVk)), asPtr(falconSk), C.size_t(len(falconSk))), "tafrah_falcon_512_keygen"); err != nil {
		return ProofResult{}, err
	}
	if err := check(C.tafrah_falcon_512_sign(asPtr(falconSk), C.size_t(len(falconSk)), asPtr(falconMsg), C.size_t(len(falconMsg)), asPtr(falconSig), C.size_t(len(falconSig)), &falconSigWritten), "tafrah_falcon_512_sign"); err != nil {
		return ProofResult{}, err
	}
	falconSig = falconSig[:int(falconSigWritten)]

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
	slhTamperRejected, err := verify(C.tafrah_slh_dsa_shake_128f_verify(asPtr(slhVk), C.size_t(len(slhVk)), asPtr(slhTampered), C.size_t(len(slhTampered)), asPtr(slhSig), C.size_t(len(slhSig))), "tafrah_slh_dsa_shake_128f_verify_tampered")
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
		Language:                    "go",
		NativeVersion:               C.GoString(C.tafrah_version()),
		MLKEM768SharedSecretMatch:   string(kemClientSS) == string(kemServerSS),
		HQC128SharedSecretMatch:     string(hqcClientSS) == string(hqcServerSS),
		MLDSA65VerifyOK:             mlVerifyOK,
		MLDSA65TamperRejected:       !mlTamperRejected,
		SLHDSAShake128FVerifyOK:     slhVerifyOK,
		SLHDSAShake128FTamperReject: !slhTamperRejected,
		Falcon512VerifyOK:           falconVerifyOK,
		Falcon512TamperRejected:     !falconTamperRejected,
	}
	out.OverallOK = out.MLKEM768SharedSecretMatch &&
		out.HQC128SharedSecretMatch &&
		out.MLDSA65VerifyOK &&
		out.MLDSA65TamperRejected &&
		out.SLHDSAShake128FVerifyOK &&
		out.SLHDSAShake128FTamperReject &&
		out.Falcon512VerifyOK &&
		out.Falcon512TamperRejected
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
