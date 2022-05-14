/*
Copyright 2020 The Flux authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package libgit2

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"testing"
	"time"

	git2go "github.com/libgit2/git2go/v33"
	. "github.com/onsi/gomega"
)

const (
	geoTrustRootFixture = `-----BEGIN CERTIFICATE-----
MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx
OTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf
BgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw
JQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH
MAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al
oCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy
MAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF
AwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9
NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9
WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw
9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy
+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi
d0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=
-----END CERTIFICATE-----`

	giag2IntermediateFixture = `-----BEGIN CERTIFICATE-----
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd
-----END CERTIFICATE-----`

	googleLeafFixture = `-----BEGIN CERTIFICATE-----
MIIEijCCA3KgAwIBAgIRAKHT0VJ6AwApElT6dyEGqWYwDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
TEMxEzARBgNVBAMTCkdUUyBDQSAxQzMwHhcNMjIwNDE4MDk0NzM2WhcNMjIwNzEx
MDk0NzM1WjAZMRcwFQYDVQQDEw53d3cuZ29vZ2xlLmNvbTBZMBMGByqGSM49AgEG
CCqGSM49AwEHA0IABEqVwVujYbkMQasddAJm62PWFmAaO0e7TBTAbRQPgeuxEcd6
dqwdfXyHONQiDPS3O15Jz89YWdYSdSnkJ6pxS1ujggJpMIICZTAOBgNVHQ8BAf8E
BAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4E
FgQUrqXrpDrss/VYXkvak4/i6uNe7zwwHwYDVR0jBBgwFoAUinR/r4XN7pXNPZzQ
4kYU83E1HScwagYIKwYBBQUHAQEEXjBcMCcGCCsGAQUFBzABhhtodHRwOi8vb2Nz
cC5wa2kuZ29vZy9ndHMxYzMwMQYIKwYBBQUHMAKGJWh0dHA6Ly9wa2kuZ29vZy9y
ZXBvL2NlcnRzL2d0czFjMy5kZXIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20w
IQYDVR0gBBowGDAIBgZngQwBAgEwDAYKKwYBBAHWeQIFAzA8BgNVHR8ENTAzMDGg
L6AthitodHRwOi8vY3Jscy5wa2kuZ29vZy9ndHMxYzMvUXFGeGJpOU00OGMuY3Js
MIIBBgYKKwYBBAHWeQIEAgSB9wSB9ADyAHcARqVV63X6kSAwtaKJafTzfREsQXS+
/Um4havy/HD+bUcAAAGAPEj6YQAABAMASDBGAiEA7SmtGTgeNtZFs6Vjy0BENToo
MvLOx1NX8paYGwHzH9sCIQCDCLwPSbL4TAhX4Q98j/9Mgtfu3gognXDGI5yU8SCU
1AB3AFGjsPX9AXmcVm24N3iPDKR6zBsny/eeiEKaDf7UiwXlAAABgDxI+qwAAAQD
AEgwRgIhAPrK6DXSDxgTkfW5OhrrX7lCUZqCGIpmWg4Vhjc1qsvaAiEA1kHlOf/X
C0oH3/F1R8vO/UFYizPVyA7a1SVhIIKC4GAwDQYJKoZIhvcNAQELBQADggEBAArJ
0YCodFNys5W9iPqNTlQIC7E07x3vU85NLmaZ4M0BddA17TgXJ1R0CwbwuTbPxAsM
b8wgQn4ZQ/mY7SoEpWjn8lBWszb1vGFkfWKhyW1Ce3BwKbdaTpGwcM4zpdW2IFzG
tinyfKFgJqWqUKdaEwarNWB+QfhUk/LEXe1LlQyBi4WTOIBinQkr750jB3tRvS+G
HvjMnKsshrCAvyY7qnzFzkCB+XxjPY91OPHRS7y0RctEMD9vV+78Dji2HKn7Fh/C
Bl1P80HvmVWW9v39r4Hd9iOvvLsy3Q1UuYcGNT/u3AFO9Fl/ETSKyk4vuvZct+Uo
wBmB6AAXkEnxae08SH0=
-----END CERTIFICATE-----`

	// googleLeafWithInvalidHashFixture is the same as googleLeafFixture, but the signature
	// algorithm in the certificate contains a nonsense OID.
	googleLeafWithInvalidHashFixture = `-----BEGIN CERTIFICATE-----
MIIEdjCCA16gAwIBAgIIcR5k4dkoe04wDQYJKoZIhvcNAWAFBQAwSTELMAkGA1UE
BhMCVVMxEzARBgNVBAoTCkdvb2dsZSBJbmMxJTAjBgNVBAMTHEdvb2dsZSBJbnRl
cm5ldCBBdXRob3JpdHkgRzIwHhcNMTQwMzEyMDkzODMwWhcNMTQwNjEwMDAwMDAw
WjBoMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwN
TW91bnRhaW4gVmlldzETMBEGA1UECgwKR29vZ2xlIEluYzEXMBUGA1UEAwwOd3d3
Lmdvb2dsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC4zYCe
m0oUBhwE0EwBr65eBOcgcQO2PaSIAB2dEP/c1EMX2tOy0ov8rk83ePhJ+MWdT1z6
jge9X4zQQI8ZyA9qIiwrKBZOi8DNUvrqNZC7fJAVRrb9aX/99uYOJCypIbpmWG1q
fhbHjJewhwf8xYPj71eU4rLG80a+DapWmphtfq3h52lDQIBzLVf1yYbyrTaELaz4
NXF7HXb5YkId/gxIsSzM0aFUVu2o8sJcLYAsJqwfFKBKOMxUcn545nlspf0mTcWZ
0APlbwsKznNs4/xCDwIxxWjjqgHrYAFl6y07i1gzbAOqdNEyR24p+3JWI8WZBlBI
dk2KGj0W1fIfsvyxAgMBAAGjggFBMIIBPTAdBgNVHSUEFjAUBggrBgEFBQcDAQYI
KwYBBQUHAwIwGQYDVR0RBBIwEIIOd3d3Lmdvb2dsZS5jb20waAYIKwYBBQUHAQEE
XDBaMCsGCCsGAQUFBzAChh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lBRzIuY3J0
MCsGCCsGAQUFBzABhh9odHRwOi8vY2xpZW50czEuZ29vZ2xlLmNvbS9vY3NwMB0G
A1UdDgQWBBTXD5Bx6iqT+dmEhbFL4OUoHyZn8zAMBgNVHRMBAf8EAjAAMB8GA1Ud
IwQYMBaAFErdBhYbvPZotXb1gba7Yhq6WoEvMBcGA1UdIAQQMA4wDAYKKwYBBAHW
eQIFATAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vcGtpLmdvb2dsZS5jb20vR0lB
RzIuY3JsMA0GCSqGSIb3DQFgBQUAA4IBAQCR3RJtHzgDh33b/MI1ugiki+nl8Ikj
5larbJRE/rcA5oite+QJyAr6SU1gJJ/rRrK3ItVEHr9L621BCM7GSdoNMjB9MMcf
tJAW0kYGJ+wqKm53wG/JaOADTnnq2Mt/j6F2uvjgN/ouns1nRHufIvd370N0LeH+
orKqTuAPzXK7imQk6+OycYABbqCtC/9qmwRd8wwn7sF97DtYfK8WuNHtFalCAwyi
8LxJJYJCLWoMhZ+V8GZm+FOex5qkQAjnZrtNlbQJ8ro4r+rpKXtmMFFhfa+7L+PA
Kom08eUK8skxAzfDDijZPh10VtJ66uBoiDPdT+uCBehcBIcmSTrKjFGX
-----END CERTIFICATE-----`

	knownHostsFixture string = `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`
)

func Test_x509Callback(t *testing.T) {
	// TODO: replace it with proper time for cert testing
	now = time.Now

	tests := []struct {
		name        string
		certificate string
		host        string
		caBundle    []byte
		want        error
	}{
		{
			name:        "Valid certificate authority bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        nil,
		},
		{
			name:        "Invalid certificate",
			certificate: googleLeafWithInvalidHashFixture,
			host:        "www.google.com",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        fmt.Errorf(`verification failed: x509: certificate signed by unknown authority (possibly because of "x509: cannot verify signature: algorithm unimplemented" while trying to verify candidate authority certificate "Google Internet Authority G2")`),
		},
		{
			name:        "Invalid certificate authority bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    bytes.Trim([]byte(giag2IntermediateFixture+"\n"+geoTrustRootFixture), "-"),
			want:        fmt.Errorf("PEM CA bundle could not be appended to x509 certificate pool"),
		},
		{
			name:        "Missing intermediate in bundle",
			certificate: googleLeafFixture,
			host:        "www.google.com",
			caBundle:    []byte(geoTrustRootFixture),
			want:        fmt.Errorf("verification failed: x509: certificate signed by unknown authority"),
		},
		{
			name:        "Invalid host",
			certificate: googleLeafFixture,
			host:        "www.google.co",
			caBundle:    []byte(giag2IntermediateFixture + "\n" + geoTrustRootFixture),
			want:        fmt.Errorf("verification failed: x509: certificate is valid for www.google.com, not www.google.co"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cert := &git2go.Certificate{}
			if tt.certificate != "" {
				x509Cert, err := certificateFromPEM(tt.certificate)
				g.Expect(err).ToNot(HaveOccurred())
				cert.X509 = x509Cert
			}

			callback := x509Callback(tt.caBundle)
			result := callback(cert, false, tt.host)
			if tt.want == nil {
				g.Expect(result).To(BeNil())
			} else {
				g.Expect(result.Error()).To(Equal(tt.want.Error()))
			}
		})
	}
}

func Test_knownHostsCallback(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		expectedHost string
		knownHosts   []byte
		hostkey      git2go.HostkeyCertificate
		want         error
	}{
		{
			name:         "Match",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com",
			want:         nil,
		},
		{
			name:         "Match with port",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "github.com:22",
			want:         nil,
		},
		{
			name:         "Hostname mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")},
			expectedHost: "example.com",
			want:         fmt.Errorf("host mismatch: %q %q", "example.com", "github.com"),
		},
		{
			name:         "Hostkey mismatch",
			host:         "github.com",
			knownHosts:   []byte(knownHostsFixture),
			hostkey:      git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\xb6\x03\x0e\x39\x97\x9e\xd0\xe7\x24\xce\xa3\x77\x3e\x01\x42\x09")},
			expectedHost: "github.com",
			want:         fmt.Errorf("hostkey could not be verified"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			cert := &git2go.Certificate{Hostkey: tt.hostkey}
			callback := knownHostsCallback(tt.expectedHost, tt.knownHosts)
			result := g.Expect(callback(cert, false, tt.host))
			if tt.want == nil {
				result.To(BeNil())
			} else {
				result.To(Equal(tt.want))
			}
		})
	}
}

func Test_parseKnownHosts_matches(t *testing.T) {
	tests := []struct {
		name        string
		hostkey     git2go.HostkeyCertificate
		wantMatches bool
	}{
		{"good sha256 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256 | git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA256: sha256Fingerprint("nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8")}, true},
		{"bad sha256 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA256 | git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA256: sha256Fingerprint("ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ")}, false},
		{"good sha1 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("v2toJdKXfFEaR1u++4iq1UqSrHM")}, true},
		{"bad sha1 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeySHA1 | git2go.HostkeyMD5, HashSHA1: sha1Fingerprint("tfpLlQhDDFP3yGdewTvHNxWmAdk")}, false},
		{"good md5 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\x16\x27\xac\xa5\x76\x28\x2d\x36\x63\x1b\x56\x4d\xeb\xdf\xa6\x48")}, true},
		{"bad md5 hostkey", git2go.HostkeyCertificate{Kind: git2go.HostkeyMD5, HashMD5: md5Fingerprint("\xb6\x03\x0e\x39\x97\x9e\xd0\xe7\x24\xce\xa3\x77\x3e\x01\x42\x09")}, false},
		{"invalid hostkey", git2go.HostkeyCertificate{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			knownKeys, err := parseKnownHosts(knownHostsFixture)
			if err != nil {
				t.Error(err)
				return
			}
			matches := knownKeys[0].matches("github.com", tt.hostkey)
			g.Expect(matches).To(Equal(tt.wantMatches))
		})
	}
}

func Test_parseKnownHosts(t *testing.T) {
	tests := []struct {
		name    string
		fixture string
		wantErr bool
	}{
		{
			name:    "empty file",
			fixture: "",
			wantErr: false,
		},
		{
			name:    "single host",
			fixture: `github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`,
			wantErr: false,
		},
		{
			name: "single host with comment",
			fixture: `# github.com
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==`,
			wantErr: false,
		},
		{
			name: "multiple hosts with comments",
			fixture: `# github.com
github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAq2A7hRGmdnm9tUDbO9IDSwBK6TbQa+PXYPCPy6rbTrTtw7PHkccKrpp0yVhp5HdEIcKr6pLlVDBfOLX9QUsyCOV0wzfjIJNlGEYsdlLJizHhbn2mUjvSAHQqZETYP81eFzLQNnPHt4EVVUh7VfDESU84KezmD5QlWpXLmvU31/yMf+Se8xhHTvKSCZIFImWwoG6mbUoWf9nzpIoaSjB+weqqUUmpaaasXVal72J+UX2B+2RPW3RcT0eOzQgqlJL3RKrTJvdsjE3JEAvGq3lGHSZXy28G3skua2SmVi/w4yCE6gbODqnTWlg7+wC604ydGXA8VJiS5ap43JXiUFFAaQ==
# gitlab.com
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf`,
		},
		{
			name: "no host key, only comments",
			fixture: `# example.com
#github.com
# gitlab.com`,
			wantErr: false,
		},
		{
			name:    "invalid host entry",
			fixture: `github.com ssh-rsa`,
			wantErr: true,
		},
		{
			name:    "invalid content",
			fixture: `some random text`,
			wantErr: true,
		},
		{
			name: "invalid line with valid host key",
			fixture: `some random text
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			_, err := parseKnownHosts(tt.fixture)
			if tt.wantErr {
				g.Expect(err).To(HaveOccurred())
			} else {
				g.Expect(err).ToNot(HaveOccurred())
			}
		})
	}
}

func Test_transferProgressCallback(t *testing.T) {
	tests := []struct {
		name       string
		progress   git2go.TransferProgress
		cancelFunc func(context.CancelFunc)
		wantErr    error
	}{
		{
			name: "ok - in progress",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 21,
			},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    nil,
		},
		{
			name: "ok - transfer complete",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 30,
			},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    nil,
		},
		{
			name: "ok - transfer complete, context cancelled",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 30,
			},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    nil,
		},
		{
			name: "error - context cancelled",
			progress: git2go.TransferProgress{
				TotalObjects:    30,
				ReceivedObjects: 21,
			},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    fmt.Errorf("transport close (potentially due to a timeout)"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			tpcb := transferProgressCallback(ctx)

			tt.cancelFunc(cancel)

			result := g.Expect(tpcb(tt.progress))
			if tt.wantErr == nil {
				result.To(BeNil())
			} else {
				result.To(Equal(tt.wantErr))
			}
		})
	}
}

func Test_transportMessageCallback(t *testing.T) {
	tests := []struct {
		name       string
		cancelFunc func(context.CancelFunc)
		wantErr    error
	}{
		{
			name:       "ok - transport open",
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    nil,
		},
		{
			name:       "error - transport closed",
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    fmt.Errorf("transport closed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			tmcb := transportMessageCallback(ctx)

			tt.cancelFunc(cancel)

			result := g.Expect(tmcb(""))
			if tt.wantErr == nil {
				result.To(BeNil())
			} else {
				result.To(Equal(tt.wantErr))
			}
		})
	}
}

func Test_pushTransferProgressCallback(t *testing.T) {
	type pushProgress struct {
		current uint32
		total   uint32
		bytes   uint
	}
	tests := []struct {
		name       string
		progress   pushProgress
		cancelFunc func(context.CancelFunc)
		wantErr    error
	}{
		{
			name:       "ok - in progress",
			progress:   pushProgress{current: 20, total: 25},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    nil,
		},
		{
			name:       "ok - transfer complete",
			progress:   pushProgress{current: 25, total: 25},
			cancelFunc: func(cf context.CancelFunc) {},
			wantErr:    nil,
		},
		{
			name:       "ok - transfer complete, context cancelled",
			progress:   pushProgress{current: 25, total: 25},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    nil,
		},
		{
			name:       "error - context cancelled",
			progress:   pushProgress{current: 20, total: 25},
			cancelFunc: func(cf context.CancelFunc) { cf() },
			wantErr:    fmt.Errorf("transport close (potentially due to a timeout)"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)

			ctx, cancel := context.WithCancel(context.TODO())
			defer cancel()

			ptpcb := pushTransferProgressCallback(ctx)

			tt.cancelFunc(cancel)

			result := g.Expect(ptpcb(tt.progress.current, tt.progress.total, tt.progress.bytes))
			if tt.wantErr == nil {
				result.To(BeNil())
			} else {
				result.To(Equal(tt.wantErr))
			}
		})
	}
}

func md5Fingerprint(in string) [16]byte {
	var out [16]byte
	copy(out[:], in)
	return out
}

func sha1Fingerprint(in string) [20]byte {
	d, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	var out [20]byte
	copy(out[:], d)
	return out
}

func sha256Fingerprint(in string) [32]byte {
	d, err := base64.RawStdEncoding.DecodeString(in)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], d)
	return out
}

func certificateFromPEM(pemBytes string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemBytes))
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}
