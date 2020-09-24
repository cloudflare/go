package hpke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

var (
	fixedPSK      = []byte{0x5d, 0xb3, 0xb8, 0x0a, 0x81, 0xcb, 0x63, 0xca, 0x59, 0x47, 0x0c, 0x83, 0x41, 0x4e, 0xf7, 0x0a}
	fixedPSKID    = []byte("Ennyn Durin aran Moria")
	original      = []byte("Beauty is truth, truth beauty")
	aad           = []byte("that is all // Ye know on earth, and all ye need to know")
	info          = []byte("Ode on a Grecian Urn")
	rtts          = 10
	exportContext = []byte("test export")
	exportLength  = 32
)

const (
	outputTestVectorEnvironmentKey = "HPKE_TEST_VECTORS_OUT"
	inputTestVectorEnvironmentKey  = "HPKE_TEST_VECTORS_IN"
	testVectorEncryptionCount      = 10
	testVectorExportCount          = 5
	testVectorExportLength         = 32
)

///////
// Infallible Serialize / Deserialize
func fatalOnError(t *testing.T, err error, msg string) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	if err != nil {
		if t != nil {
			t.Fatalf(realMsg)
		} else {
			panic(realMsg)
		}
	}
}

func mustUnhex(t *testing.T, h string) []byte {
	out, err := hex.DecodeString(h)
	fatalOnError(t, err, "Unhex failed")
	return out
}

func mustHex(d []byte) string {
	return hex.EncodeToString(d)
}

func mustDeserializePriv(t *testing.T, suite CipherSuite, h string, required bool) KEMPrivateKey {
	skm := mustUnhex(t, h)
	sk, err := suite.KEM.DeserializePrivate(skm)
	if required {
		fatalOnError(t, err, "DeserializePrivate failed")
	}
	return sk
}

func mustSerializePriv(suite CipherSuite, priv KEMPrivateKey) string {
	return mustHex(suite.KEM.SerializePrivate(priv))
}

func mustDeserializePub(t *testing.T, suite CipherSuite, h string, required bool) KEMPublicKey {
	pkm := mustUnhex(t, h)
	pk, err := suite.KEM.Deserialize(pkm)
	if required {
		fatalOnError(t, err, "Deserialize failed")
	}
	return pk
}

func mustSerializePub(suite CipherSuite, pub KEMPublicKey) string {
	return mustHex(suite.KEM.Serialize(pub))
}

func mustGenerateKeyPair(t *testing.T, suite CipherSuite) (KEMPrivateKey, KEMPublicKey, []byte) {
	ikm := make([]byte, suite.KEM.PrivateKeySize())
	rand.Reader.Read(ikm)
	sk, pk, err := suite.KEM.DeriveKeyPair(ikm)
	fatalOnError(t, err, "Error generating DH key pair")
	return sk, pk, ikm
}

///////
// Assertions
func assert(t *testing.T, suite CipherSuite, msg string, test bool) {
	if !test {
		t.Fatalf("[%04x, %04x, %04x] %s", suite.KEM.ID(), suite.KDF.ID(), suite.AEAD.ID(), msg)
	}
}

func assertNotError(t *testing.T, suite CipherSuite, msg string, err error) {
	realMsg := fmt.Sprintf("%s: %v", msg, err)
	assert(t, suite, realMsg, err == nil)
}

func assertBytesEqual(t *testing.T, suite CipherSuite, msg string, lhs, rhs []byte) {
	realMsg := fmt.Sprintf("%s: [%x] != [%x]", msg, lhs, rhs)
	assert(t, suite, realMsg, bytes.Equal(lhs, rhs))
}

func assertCipherContextEqual(t *testing.T, suite CipherSuite, msg string, lhs, rhs context) {
	// Verify the serialized fields match.
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "role"), lhs.Role == rhs.Role)
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "KEM id"), lhs.KEMID == rhs.KEMID)
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "KDF id"), lhs.KDFID == rhs.KDFID)
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "AEAD id"), lhs.AEADID == rhs.AEADID)
	assertBytesEqual(t, suite, fmt.Sprintf("%s: %s", msg, "exporter secret"), lhs.ExporterSecret, rhs.ExporterSecret)
	assertBytesEqual(t, suite, fmt.Sprintf("%s: %s", msg, "key"), lhs.Key, rhs.Key)
	assertBytesEqual(t, suite, fmt.Sprintf("%s: %s", msg, "nonce"), lhs.Nonce, rhs.Nonce)
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "sequence number"), lhs.Seq == rhs.Seq)

	// Verify that the internal AEAD object uses the same algorithm and is keyed
	// with the same key.
	var got, want []byte
	lhs.aead.Seal(got, lhs.Nonce, nil, nil)
	rhs.aead.Seal(want, rhs.Nonce, nil, nil)
	assertBytesEqual(t, suite, fmt.Sprintf("%s: %s", msg, "internal AEAD representation"), got, want)

	// Verify that the internal representation of the cipher suite matches.
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "KEM scheme representation"), lhs.suite.KEM.ID() == rhs.suite.KEM.ID())
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "KDF scheme representation"), lhs.suite.KDF.ID() == rhs.suite.KDF.ID())
	assert(t, suite, fmt.Sprintf("%s: %s", msg, "AEAD scheme representation"), lhs.suite.AEAD.ID() == rhs.suite.AEAD.ID())
}

///////
// Symmetric encryption test vector structure
type encryptionTestVector struct {
	plaintext  []byte
	aad        []byte
	nonce      []byte
	ciphertext []byte
}

func (etv encryptionTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"plaintext":  mustHex(etv.plaintext),
		"aad":        mustHex(etv.aad),
		"nonce":      mustHex(etv.nonce),
		"ciphertext": mustHex(etv.ciphertext),
	})
}

func (etv *encryptionTestVector) UnmarshalJSON(data []byte) error {
	raw := map[string]string{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.plaintext = mustUnhex(nil, raw["plaintext"])
	etv.aad = mustUnhex(nil, raw["aad"])
	etv.nonce = mustUnhex(nil, raw["nonce"])
	etv.ciphertext = mustUnhex(nil, raw["ciphertext"])
	return nil
}

///////
// Exporter test vector structures
type rawExporterTestVector struct {
	ExportContext string `json:"exportContext"`
	ExportLength  int    `json:"exportLength"`
	ExportValue   string `json:"exportValue"`
}

type exporterTestVector struct {
	exportContext []byte
	exportLength  int
	exportValue   []byte
}

func (etv exporterTestVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawExporterTestVector{
		ExportContext: mustHex(etv.exportContext),
		ExportLength:  etv.exportLength,
		ExportValue:   mustHex(etv.exportValue),
	})
}

func (etv *exporterTestVector) UnmarshalJSON(data []byte) error {
	raw := rawExporterTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	etv.exportContext = mustUnhex(nil, raw.ExportContext)
	etv.exportLength = raw.ExportLength
	etv.exportValue = mustUnhex(nil, raw.ExportValue)
	return nil
}

///////
// HPKE test vector structures
type rawTestVector struct {
	// Parameters
	Mode   Mode   `json:"mode"`
	KEMID  KEMID  `json:"kem_id"`
	KDFID  KDFID  `json:"kdf_id"`
	AEADID AEADID `json:"aead_id"`
	Info   string `json:"info"`

	// Private keys
	SeedR string `json:"seedR"`
	SeedS string `json:"seedS,omitempty"`
	SeedE string `json:"seedE"`
	SKR   string `json:"skRm"`
	SKS   string `json:"skSm,omitempty"`
	SKE   string `json:"skEm"`
	PSK   string `json:"psk,omitempty"`
	PSKID string `json:"psk_id,omitempty"`

	// Public keys
	PKR string `json:"pkRm"`
	PKS string `json:"pkSm,omitempty"`
	PKE string `json:"pkEm"`

	// Key schedule inputs and computations
	Enc                string `json:"enc"`
	SharedSecret       string `json:"shared_secret"`
	KeyScheduleContext string `json:"key_schedule_context"`
	Secret             string `json:"secret"`
	Key                string `json:"key"`
	Nonce              string `json:"nonce"`
	ExporterSecret     string `json:"exporter_secret"`

	Encryptions []encryptionTestVector `json:"encryptions"`
	Exports     []exporterTestVector   `json:"exports"`
}

type testVector struct {
	t     *testing.T
	suite CipherSuite

	// Parameters
	mode    Mode
	kem_id  KEMID
	kdf_id  KDFID
	aead_id AEADID
	info    []byte

	// Private keys
	skR    KEMPrivateKey
	skS    KEMPrivateKey
	skE    KEMPrivateKey
	seedR  []byte
	seedS  []byte
	seedE  []byte
	psk    []byte
	psk_id []byte

	// Public keys
	pkR KEMPublicKey
	pkS KEMPublicKey
	pkE KEMPublicKey

	// Key schedule inputs and computations
	enc                []byte
	sharedSecret       []byte
	keyScheduleContext []byte
	secret             []byte
	key                []byte
	nonce              []byte
	exporterSecret     []byte

	encryptions []encryptionTestVector
	exports     []exporterTestVector
}

func (tv testVector) MarshalJSON() ([]byte, error) {
	return json.Marshal(rawTestVector{
		Mode:   tv.mode,
		KEMID:  tv.kem_id,
		KDFID:  tv.kdf_id,
		AEADID: tv.aead_id,
		Info:   mustHex(tv.info),

		SeedR: mustHex(tv.seedR),
		SeedS: mustHex(tv.seedS),
		SeedE: mustHex(tv.seedE),
		SKR:   mustSerializePriv(tv.suite, tv.skR),
		SKS:   mustSerializePriv(tv.suite, tv.skS),
		SKE:   mustSerializePriv(tv.suite, tv.skE),
		PSK:   mustHex(tv.psk),
		PSKID: mustHex(tv.psk_id),

		PKR: mustSerializePub(tv.suite, tv.pkR),
		PKS: mustSerializePub(tv.suite, tv.pkS),
		PKE: mustSerializePub(tv.suite, tv.pkE),

		Enc:                mustHex(tv.enc),
		SharedSecret:       mustHex(tv.sharedSecret),
		KeyScheduleContext: mustHex(tv.keyScheduleContext),
		Secret:             mustHex(tv.secret),
		Key:                mustHex(tv.key),
		Nonce:              mustHex(tv.nonce),
		ExporterSecret:     mustHex(tv.exporterSecret),

		Encryptions: tv.encryptions,
		Exports:     tv.exports,
	})
}

func (tv *testVector) UnmarshalJSON(data []byte) error {
	raw := rawTestVector{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return err
	}

	tv.mode = raw.Mode
	tv.kem_id = raw.KEMID
	tv.kdf_id = raw.KDFID
	tv.aead_id = raw.AEADID
	tv.info = mustUnhex(tv.t, raw.Info)

	tv.suite, err = AssembleCipherSuite(raw.KEMID, raw.KDFID, raw.AEADID)
	if err != nil {
		return err
	}

	modeRequiresSenderKey := (tv.mode == modeAuth || tv.mode == modeAuthPSK)
	tv.skR = mustDeserializePriv(tv.t, tv.suite, raw.SKR, true)
	tv.skS = mustDeserializePriv(tv.t, tv.suite, raw.SKS, modeRequiresSenderKey)
	tv.skE = mustDeserializePriv(tv.t, tv.suite, raw.SKE, true)

	tv.pkR = mustDeserializePub(tv.t, tv.suite, raw.PKR, true)
	tv.pkS = mustDeserializePub(tv.t, tv.suite, raw.PKS, modeRequiresSenderKey)
	tv.pkE = mustDeserializePub(tv.t, tv.suite, raw.PKE, true)

	tv.psk = mustUnhex(tv.t, raw.PSK)
	tv.psk_id = mustUnhex(tv.t, raw.PSKID)

	tv.seedR = mustUnhex(tv.t, raw.SeedR)
	tv.seedS = mustUnhex(tv.t, raw.SeedS)
	tv.seedE = mustUnhex(tv.t, raw.SeedE)

	tv.enc = mustUnhex(tv.t, raw.Enc)
	tv.sharedSecret = mustUnhex(tv.t, raw.SharedSecret)
	tv.keyScheduleContext = mustUnhex(tv.t, raw.KeyScheduleContext)
	tv.secret = mustUnhex(tv.t, raw.Secret)
	tv.key = mustUnhex(tv.t, raw.Key)
	tv.nonce = mustUnhex(tv.t, raw.Nonce)
	tv.exporterSecret = mustUnhex(tv.t, raw.ExporterSecret)

	tv.encryptions = raw.Encryptions
	tv.exports = raw.Exports
	return nil
}

type testVectorArray struct {
	t       *testing.T
	vectors []testVector
}

func (tva testVectorArray) MarshalJSON() ([]byte, error) {
	return json.Marshal(tva.vectors)
}

func (tva *testVectorArray) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &tva.vectors)
	if err != nil {
		return err
	}

	for i := range tva.vectors {
		tva.vectors[i].t = tva.t
	}
	return nil
}

///////
// Generalize setup functions so that we can iterate over them easily
type setupMode struct {
	Mode Mode
	OK   func(suite CipherSuite) bool
	I    func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *EncryptContext, error)
	R    func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*DecryptContext, error)
}

var setupModes = map[Mode]setupMode{
	modeBase: {
		Mode: modeBase,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *EncryptContext, error) {
			return SetupBaseS(suite, rand.Reader, pkR, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*DecryptContext, error) {
			return SetupBaseR(suite, skR, enc, info)
		},
	},
	modePSK: {
		Mode: modePSK,
		OK:   func(suite CipherSuite) bool { return true },
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *EncryptContext, error) {
			return SetupPSKS(suite, rand.Reader, pkR, psk, psk_id, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*DecryptContext, error) {
			return SetupPSKR(suite, skR, enc, psk, psk_id, info)
		},
	},
	modeAuth: {
		Mode: modeAuth,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *EncryptContext, error) {
			return SetupAuthS(suite, rand.Reader, pkR, skS, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*DecryptContext, error) {
			return SetupAuthR(suite, skR, pkS, enc, info)
		},
	},
	modeAuthPSK: {
		Mode: modeAuthPSK,
		OK: func(suite CipherSuite) bool {
			_, ok := suite.KEM.(AuthKEMScheme)
			return ok
		},
		I: func(suite CipherSuite, pkR KEMPublicKey, info []byte, skS KEMPrivateKey, psk, psk_id []byte) ([]byte, *EncryptContext, error) {
			return SetupAuthPSKS(suite, rand.Reader, pkR, skS, psk, psk_id, info)
		},
		R: func(suite CipherSuite, skR KEMPrivateKey, enc, info []byte, pkS KEMPublicKey, psk, psk_id []byte) (*DecryptContext, error) {
			return SetupAuthPSKR(suite, skR, pkS, enc, psk, psk_id, info)
		},
	},
}

///////
// Direct tests

type roundTripTest struct {
	kem_id  KEMID
	kdf_id  KDFID
	aead_id AEADID
	setup   setupMode
}

func (rtt roundTripTest) Test(t *testing.T) {
	suite, err := AssembleCipherSuite(rtt.kem_id, rtt.kdf_id, rtt.aead_id)
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error looking up ciphersuite: %v", rtt.kem_id, rtt.kdf_id, rtt.aead_id, err)
	}

	if !rtt.setup.OK(suite) {
		return
	}

	skS, pkS, _ := mustGenerateKeyPair(t, suite)
	skR, pkR, _ := mustGenerateKeyPair(t, suite)

	enc, ctxI, err := rtt.setup.I(suite, pkR, info, skS, fixedPSK, fixedPSKID)
	assertNotError(t, suite, "Error in SetupI", err)

	ctxR, err := rtt.setup.R(suite, skR, enc, info, pkS, fixedPSK, fixedPSKID)
	assertNotError(t, suite, "Error in SetupR", err)

	// Verify encryption functionality
	for range make([]struct{}, rtts) {
		encrypted := ctxI.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		assertNotError(t, suite, "Error in Open", err)
		assertBytesEqual(t, suite, "Incorrect decryption", decrypted, original)
	}

	// Verify exporter functionality
	exportedI := ctxI.Export(exportContext, exportLength)
	exportedR := ctxR.Export(exportContext, exportLength)
	assertBytesEqual(t, suite, "Incorrect exported secret", exportedI, exportedR)

	// Verify encryption context serialization functionality
	opaqueI, err := ctxI.Marshal()
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error serializing encrypt context: %v", rtt.kem_id, rtt.kdf_id, rtt.aead_id, err)
	}

	unmarshaledI, err := UnmarshalEncryptContext(opaqueI)
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error serializing encrypt context: %v", rtt.kem_id, rtt.kdf_id, rtt.aead_id, err)
	}

	assertCipherContextEqual(t, suite, "Encrypt context serialization mismatch", ctxI.context, unmarshaledI.context)

	// Verify decryption context serialization functionality
	opaqueR, err := ctxR.Marshal()
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error serializing decrypt context: %v", rtt.kem_id, rtt.kdf_id, rtt.aead_id, err)
	}

	unmarshaledR, err := UnmarshalDecryptContext(opaqueR)
	if err != nil {
		t.Fatalf("[%04x, %04x, %04x] Error serializing decrypt context: %v", rtt.kem_id, rtt.kdf_id, rtt.aead_id, err)
	}

	assertCipherContextEqual(t, suite, "Decrypt context serialization mismatch", ctxR.context, unmarshaledR.context)

	// Verify exporter functionality for a deserialized context
	assertBytesEqual(t, suite, "Export after serialization fails for sender", exportedI, unmarshaledI.Export(exportContext, exportLength))
	assertBytesEqual(t, suite, "Export after serialization fails for receiver", exportedR, unmarshaledR.Export(exportContext, exportLength))
}

func TestModes(t *testing.T) {
	for kem_id, _ := range kems {
		for kdf_id, _ := range kdfs {
			for aead_id, _ := range aeads {
				for mode, setup := range setupModes {
					label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", kem_id, kdf_id, aead_id, mode)
					rtt := roundTripTest{kem_id, kdf_id, aead_id, setup}
					t.Run(label, rtt.Test)
				}
			}
		}
	}
}

///////
// Generation and processing of test vectors

func verifyEncryptions(tv testVector, enc *EncryptContext, dec *DecryptContext) {
	for _, data := range tv.encryptions {
		encrypted := enc.Seal(data.aad, data.plaintext)
		decrypted, err := dec.Open(data.aad, encrypted)

		assertNotError(tv.t, tv.suite, "Error in Open", err)
		assertBytesEqual(tv.t, tv.suite, "Incorrect encryption", encrypted, data.ciphertext)
		assertBytesEqual(tv.t, tv.suite, "Incorrect decryption", decrypted, data.plaintext)
	}
}

func verifyParameters(tv testVector, ctx context) {
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'shared_secret'", tv.sharedSecret, ctx.setupParams.sharedSecret)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'enc'", tv.enc, ctx.setupParams.enc)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'key_schedule_context'", tv.keyScheduleContext, ctx.contextParams.keyScheduleContext)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'secret'", tv.secret, ctx.contextParams.secret)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'key'", tv.key, ctx.Key)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'nonce'", tv.nonce, ctx.Nonce)
	assertBytesEqual(tv.t, tv.suite, "Incorrect parameter 'exporter_secret'", tv.exporterSecret, ctx.ExporterSecret)
}

func verifyPublicKeysEqual(tv testVector, pkX, pkY KEMPublicKey) {
	pkXm := mustSerializePub(tv.suite, pkX)
	pkYm := mustSerializePub(tv.suite, pkY)
	assertBytesEqual(tv.t, tv.suite, "Incorrect public key", []byte(pkXm), []byte(pkYm))
}

func verifyPrivateKeysEqual(tv testVector, skX, skY KEMPrivateKey) {
	skXm := mustSerializePriv(tv.suite, skX)
	skYm := mustSerializePriv(tv.suite, skY)
	assertBytesEqual(tv.t, tv.suite, "Incorrect private key", []byte(skXm), []byte(skYm))
}

func verifyTestVector(tv testVector) {
	setup := setupModes[tv.mode]

	skR, pkR, err := tv.suite.KEM.DeriveKeyPair(tv.seedR)
	assertNotError(tv.t, tv.suite, "Error in DeriveKeyPair", err)
	verifyPublicKeysEqual(tv, tv.pkR, pkR)
	verifyPrivateKeysEqual(tv, tv.skR, skR)

	skE, pkE, err := tv.suite.KEM.DeriveKeyPair(tv.seedE)
	assertNotError(tv.t, tv.suite, "Error in DeriveKeyPair", err)
	verifyPublicKeysEqual(tv, tv.pkE, pkE)
	verifyPrivateKeysEqual(tv, tv.skE, skE)

	tv.suite.KEM.setEphemeralKeyPair(skE)

	var pkS KEMPublicKey
	var skS KEMPrivateKey
	if setup.Mode == modeAuth || setup.Mode == modeAuthPSK {
		skS, pkS, err = tv.suite.KEM.DeriveKeyPair(tv.seedS)
		assertNotError(tv.t, tv.suite, "Error in DeriveKeyPair", err)
		verifyPublicKeysEqual(tv, tv.pkS, pkS)
		verifyPrivateKeysEqual(tv, tv.skS, skS)
	}

	enc, ctxI, err := setup.I(tv.suite, pkR, tv.info, skS, tv.psk, tv.psk_id)
	assertNotError(tv.t, tv.suite, "Error in SetupI", err)
	assertBytesEqual(tv.t, tv.suite, "Encapsulated key mismatch", enc, tv.enc)

	ctxR, err := setup.R(tv.suite, skR, tv.enc, tv.info, pkS, tv.psk, tv.psk_id)
	assertNotError(tv.t, tv.suite, "Error in SetupR", err)

	verifyParameters(tv, ctxI.context)
	verifyParameters(tv, ctxR.context)

	verifyEncryptions(tv, ctxI, ctxR)
}

func vectorTest(vector testVector) func(t *testing.T) {
	return func(t *testing.T) {
		verifyTestVector(vector)
	}
}

func verifyTestVectors(t *testing.T, vectorString []byte, subtest bool) {
	vectors := testVectorArray{t: t}
	err := json.Unmarshal(vectorString, &vectors)
	if err != nil {
		t.Fatalf("Error decoding test vector string: %v", err)
	}

	for _, tv := range vectors.vectors {
		test := vectorTest(tv)
		if !subtest {
			test(t)
		} else {
			label := fmt.Sprintf("kem=%04x/kdf=%04x/aead=%04x/mode=%02x", tv.kem_id, tv.kdf_id, tv.aead_id, tv.mode)
			t.Run(label, test)
		}
	}
}

func generateEncryptions(t *testing.T, suite CipherSuite, ctxI *EncryptContext, ctxR *DecryptContext) ([]encryptionTestVector, error) {
	vectors := make([]encryptionTestVector, testVectorEncryptionCount)
	for i := 0; i < len(vectors); i++ {
		aad := []byte(fmt.Sprintf("Count-%d", i))
		encrypted := ctxI.Seal(aad, original)
		decrypted, err := ctxR.Open(aad, encrypted)
		assertNotError(t, suite, "Decryption failure", err)
		assertBytesEqual(t, suite, "Incorrect decryption", original, decrypted)

		vectors[i] = encryptionTestVector{
			plaintext:  original,
			aad:        aad,
			nonce:      ctxI.nonces[i],
			ciphertext: encrypted,
		}
	}

	return vectors, nil
}

func generateExports(t *testing.T, suite CipherSuite, ctxI *EncryptContext, ctxR *DecryptContext) ([]exporterTestVector, error) {
	vectors := make([]exporterTestVector, testVectorExportCount)
	for i := 0; i < len(vectors); i++ {
		context := []byte(fmt.Sprintf("Context-%d", i))
		exportI := ctxI.Export(context, testVectorExportLength)
		exportR := ctxR.Export(context, testVectorExportLength)
		assertBytesEqual(t, suite, "Incorrect export", exportI, exportR)
		vectors[i] = exporterTestVector{
			exportContext: context,
			exportLength:  testVectorExportLength,
			exportValue:   exportI,
		}
	}

	return vectors, nil
}

func generateTestVector(t *testing.T, setup setupMode, kem_id KEMID, kdf_id KDFID, aead_id AEADID) testVector {
	suite, err := AssembleCipherSuite(kem_id, kdf_id, aead_id)
	if err != nil {
		t.Fatalf("[%x, %x, %x] Error looking up ciphersuite: %s", kem_id, kdf_id, aead_id, err)
	}

	skR, pkR, seedR := mustGenerateKeyPair(t, suite)
	skE, pkE, seedE := mustGenerateKeyPair(t, suite)

	// The sender key share is only required for Auth mode variants.
	var pkS KEMPublicKey
	var skS KEMPrivateKey
	var seedS []byte
	if setup.Mode == modeAuth || setup.Mode == modeAuthPSK {
		skS, pkS, seedS = mustGenerateKeyPair(t, suite)
	}

	// A PSK is only required for PSK mode variants.
	var psk []byte
	var psk_id []byte
	if setup.Mode == modePSK || setup.Mode == modeAuthPSK {
		psk = fixedPSK
		psk_id = fixedPSKID
	}

	suite.KEM.setEphemeralKeyPair(skE)

	enc, ctxI, err := setup.I(suite, pkR, info, skS, psk, psk_id)
	assertNotError(t, suite, "Error in SetupPSKS", err)

	ctxR, err := setup.R(suite, skR, enc, info, pkS, psk, psk_id)
	assertNotError(t, suite, "Error in SetupPSKR", err)

	encryptionVectors, err := generateEncryptions(t, suite, ctxI, ctxR)
	assertNotError(t, suite, "Error in generateEncryptions", err)

	exportVectors, err := generateExports(t, suite, ctxI, ctxR)
	assertNotError(t, suite, "Error in generateExports", err)

	vector := testVector{
		t:                  t,
		suite:              suite,
		mode:               setup.Mode,
		kem_id:             kem_id,
		kdf_id:             kdf_id,
		aead_id:            aead_id,
		info:               info,
		skR:                skR,
		pkR:                pkR,
		skS:                skS,
		pkS:                pkS,
		skE:                skE,
		pkE:                pkE,
		seedR:              seedR,
		seedS:              seedS,
		seedE:              seedE,
		psk:                psk,
		psk_id:             psk_id,
		enc:                ctxI.setupParams.enc,
		sharedSecret:       ctxI.setupParams.sharedSecret,
		keyScheduleContext: ctxI.contextParams.keyScheduleContext,
		secret:             ctxI.contextParams.secret,
		key:                ctxI.Key,
		nonce:              ctxI.Nonce,
		exporterSecret:     ctxI.ExporterSecret,
		encryptions:        encryptionVectors,
		exports:            exportVectors,
	}

	return vector
}

func TestVectorGenerate(t *testing.T) {
	// We only generate test vectors for select ciphersuites
	supportedKEMs := []KEMID{DHKEM_X25519, DHKEM_P256, DHKEM_P521}
	supportedKDFs := []KDFID{KDF_HKDF_SHA256, KDF_HKDF_SHA512}
	supportedAEADs := []AEADID{AEAD_AESGCM128, AEAD_AESGCM256, AEAD_CHACHA20POLY1305}

	vectors := make([]testVector, 0)
	for _, kem_id := range supportedKEMs {
		for _, kdf_id := range supportedKDFs {
			for _, aead_id := range supportedAEADs {
				for _, setup := range setupModes {
					vectors = append(vectors, generateTestVector(t, setup, kem_id, kdf_id, aead_id))
				}
			}
		}
	}

	// Encode the test vectors
	encoded, err := json.Marshal(vectors)
	if err != nil {
		t.Fatalf("Error producing test vectors: %v", err)
	}

	// Verify that we process them correctly
	verifyTestVectors(t, encoded, false)

	// Write them to a file if requested
	var outputFile string
	if outputFile = os.Getenv(outputTestVectorEnvironmentKey); len(outputFile) > 0 {
		err = ioutil.WriteFile(outputFile, encoded, 0644)
		if err != nil {
			t.Fatalf("Error writing test vectors: %v", err)
		}
	}
}

func TestVectorVerify(t *testing.T) {
	var inputFile string
	if inputFile = os.Getenv(inputTestVectorEnvironmentKey); len(inputFile) == 0 {
		t.Skip("Test vectors were not provided")
	}

	encoded, err := ioutil.ReadFile(inputFile)
	if err != nil {
		t.Fatalf("Failed reading test vectors: %v", err)
	}

	verifyTestVectors(t, encoded, true)
}
