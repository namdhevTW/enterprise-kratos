package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

// TestDefaultNotNil verifies that Default() returns a non-nil pointer.
func TestDefaultNotNil(t *testing.T) {
	t.Parallel()
	if Default() == nil {
		t.Fatal("Default() returned nil; want non-nil *FlowPolicy")
	}
}

// TestDefaultLoginAllowedFirstFactors checks the initial first-factor list.
func TestDefaultLoginAllowedFirstFactors(t *testing.T) {
	t.Parallel()
	got := Default().Login.AllowedFirstFactors
	want := []string{"password"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AllowedFirstFactors = %v; want %v", got, want)
	}
}

// TestDefaultLoginAllowedSecondFactorsEmpty verifies that no second factors are
// configured in the default policy.
func TestDefaultLoginAllowedSecondFactorsEmpty(t *testing.T) {
	t.Parallel()
	got := Default().Login.AllowedSecondFactors
	if len(got) != 0 {
		t.Errorf("AllowedSecondFactors = %v; want empty slice", got)
	}
}

// TestDefaultLoginMFARequired ensures MFA is off by default.
func TestDefaultLoginMFARequired(t *testing.T) {
	t.Parallel()
	if got := Default().Login.MFARequired; got != false {
		t.Errorf("MFARequired = %v; want false", got)
	}
}

// TestDefaultLoginSSOOnly ensures SSO-only mode is off by default.
func TestDefaultLoginSSOOnly(t *testing.T) {
	t.Parallel()
	if got := Default().Login.SSOOnly; got != false {
		t.Errorf("SSOOnly = %v; want false", got)
	}
}

// TestDefaultRegistrationEnabled checks that registration is enabled by default.
func TestDefaultRegistrationEnabled(t *testing.T) {
	t.Parallel()
	if got := Default().Registration.Enabled; got != true {
		t.Errorf("Registration.Enabled = %v; want true", got)
	}
}

// TestDefaultRegistrationRequireVerification checks that email verification is
// not required in the default policy.
func TestDefaultRegistrationRequireVerification(t *testing.T) {
	t.Parallel()
	if got := Default().Registration.RequireVerification; got != false {
		t.Errorf("Registration.RequireVerification = %v; want false", got)
	}
}

// TestDefaultSessionTTL verifies the default session time-to-live.
func TestDefaultSessionTTL(t *testing.T) {
	t.Parallel()
	if got := Default().Session.TTL; got != "24h" {
		t.Errorf("Session.TTL = %q; want %q", got, "24h")
	}
}

// TestDefaultSessionRequiredAAL verifies the default authenticator assurance level.
func TestDefaultSessionRequiredAAL(t *testing.T) {
	t.Parallel()
	if got := Default().Session.RequiredAAL; got != "aal1" {
		t.Errorf("Session.RequiredAAL = %q; want %q", got, "aal1")
	}
}

// TestDefaultSessionInactivityTimeout verifies the default inactivity timeout.
func TestDefaultSessionInactivityTimeout(t *testing.T) {
	t.Parallel()
	if got := Default().Session.InactivityTimeout; got != "1h" {
		t.Errorf("Session.InactivityTimeout = %q; want %q", got, "1h")
	}
}

// TestDefaultRecoveryEnabled checks that account recovery is enabled by default.
func TestDefaultRecoveryEnabled(t *testing.T) {
	t.Parallel()
	if got := Default().Recovery.Enabled; got != true {
		t.Errorf("Recovery.Enabled = %v; want true", got)
	}
}

// TestDefaultRecoveryAllowedMethods checks the default recovery method list.
func TestDefaultRecoveryAllowedMethods(t *testing.T) {
	t.Parallel()
	got := Default().Recovery.AllowedMethods
	want := []string{"link"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Recovery.AllowedMethods = %v; want %v", got, want)
	}
}

// TestJSONRoundTrip marshals a default FlowPolicy to JSON and back, confirming
// that the decoded value is deeply equal to the original.
func TestJSONRoundTrip(t *testing.T) {
	t.Parallel()
	original := Default()

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded FlowPolicy
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if !reflect.DeepEqual(*original, decoded) {
		t.Errorf("round-trip mismatch:\noriginal: %+v\ndecoded:  %+v", *original, decoded)
	}
}

// TestTopLevelJSONKeys verifies that the top-level keys in the marshalled output
// are exactly: login, registration, session, recovery.
func TestTopLevelJSONKeys(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Default())
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal into map: %v", err)
	}

	wantKeys := []string{"login", "registration", "session", "recovery"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("top-level JSON key %q not found in output", key)
		}
	}
	if got := len(raw); got != len(wantKeys) {
		t.Errorf("unexpected number of top-level keys: got %d, want %d", got, len(wantKeys))
	}
}

// TestLoginPolicyJSONKeys verifies the JSON field names for LoginPolicy.
func TestLoginPolicyJSONKeys(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Default().Login)
	if err != nil {
		t.Fatalf("json.Marshal LoginPolicy: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal LoginPolicy map: %v", err)
	}

	wantKeys := []string{"allowed_first_factors", "allowed_second_factors", "mfa_required", "sso_only"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("LoginPolicy JSON key %q not found", key)
		}
	}
}

// TestRegistrationPolicyJSONKeys verifies the JSON field names for RegistrationPolicy.
func TestRegistrationPolicyJSONKeys(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Default().Registration)
	if err != nil {
		t.Fatalf("json.Marshal RegistrationPolicy: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal RegistrationPolicy map: %v", err)
	}

	wantKeys := []string{"enabled", "require_verification"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("RegistrationPolicy JSON key %q not found", key)
		}
	}
}

// TestSessionPolicyJSONKeys verifies the JSON field names for SessionPolicy.
func TestSessionPolicyJSONKeys(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Default().Session)
	if err != nil {
		t.Fatalf("json.Marshal SessionPolicy: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal SessionPolicy map: %v", err)
	}

	wantKeys := []string{"ttl", "required_aal", "inactivity_timeout"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("SessionPolicy JSON key %q not found", key)
		}
	}
}

// TestRecoveryPolicyJSONKeys verifies the JSON field names for RecoveryPolicy.
func TestRecoveryPolicyJSONKeys(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(Default().Recovery)
	if err != nil {
		t.Fatalf("json.Marshal RecoveryPolicy: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal RecoveryPolicy map: %v", err)
	}

	wantKeys := []string{"enabled", "allowed_methods"}
	for _, key := range wantKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("RecoveryPolicy JSON key %q not found", key)
		}
	}
}
