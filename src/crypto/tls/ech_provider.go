package tls

// ECHProvider specifies the interface of an ECH service provider that decrypts
// the ECH payload on behalf of the client-facing server. It also defines the
// set of acceptable ECH configurations.
type ECHProvider interface {
	// GetContext attempts to construct the HPKE context used by the
	// client-facing server for decryption. (See draft-irtf-cfrg-hpke-05,
	// Section 5.2.)
	//
	// handle encodes the parameters of the client's "encrypted_client_hello"
	// extension that are needed to construct the context. In
	// draft-ietf-tls-esni-08, these are the ECH cipher suite, the identity of
	// the ECH configuration, and the encapsulated key.
	//
	// hrrPsk is the PSK used to construct the context. This is set by the
	// caller in case the server previously sent a HelloRetryRequest in this
	// connection. Otherwise, len(hrrPsk) == 0.
	//
	// version is the version of ECH indicated by the client.
	//
	// res.Status == ECHProviderStatusSuccess indicates the call was successful
	// and the caller may proceed. res.Context is set.
	//
	// res.Status == ECHProviderStatusReject indicates the caller must reject
	// ECH. res.RetryConfigs may be set.
	//
	// res.Status == ECHProviderStatusAbort indicates the caller must abort the
	// handshake. res.Alert and res.Error are set.
	GetContext(handle, hrrPsk []byte, version uint16) (res ECHProviderResult)
}

// ECHProviderStatus is the status of the ECH provider's response.
type ECHProviderStatus uint

const (
	ECHProviderSuccess ECHProviderStatus = 0
	ECHProviderReject                    = 1
	ECHProviderAbort                     = 2
)

// ECHProviderResult represents the result of invoking the ECH provider.
type ECHProviderResult struct {
	Status ECHProviderStatus

	// Alert is the TLS alert sent by the caller when aborting the handshake.
	Alert uint8

	// Error is the error propagated by the caller when aborting the handshake.
	Error error

	// RetryConfigs is the sequence of ECH configs to offer to the client for
	// retrying the handshake. This may be set in case of success or rejection.
	RetryConfigs []byte

	// Context is the server's HPKE context. This is set if ECH is not rejected
	// by the provider and no error was reported. The data has the following
	// format (in TLS syntax):
	//
	// enum { sender(0), receiver(1) } HpkeRole;
	//
	// struct {
	//     HpkeRole role;
	//     HpkeKemId kem_id;   // as defined in draft-irtf-cfrg-hpke-05
	//     HpkeKdfId kdf_id;   // as defined in draft-irtf-cfrg-hpke-05
	//     HpkeAeadId aead_id; // as defined in draft-irtf-cfrg-hpke-05
	//     opaque exporter_secret<0..255>;
	//     opaque key<0..255>;
	//     opaque nonce<0..255>;
	//     uint64 seq;
	// } HpkeContext;
	//
	// NOTE(cjpatton): This format is specified neither in the ECH spec nor the
	// HPKE spec. It is the format chosen for the HPKE implementation that we're
	// using. See
	// https://github.com/cisco/go-hpke/blob/9e7d3e90b7c3a5b08f3099c49520c587568c77d6/hpke.go#L198
	Context []byte
}
