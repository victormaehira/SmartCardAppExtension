//
//  Token.swift
//  AppExtension
//
//  Created by Victor Yuji Maehira on 23/03/26.
//

import CryptoTokenKit
import Security

class Token: TKSmartCardToken, TKTokenDelegate {
    /// DER X.509 em Base64 (sem cabeçalho PEM). Ex.: `openssl x509 -in cert.pem -outform DER | base64`
    private static let mockCertificateDERBase64 = "MIIFfDCCA2SgAwIBAgIIEt6nQ2Ejuz0wDQYJKoZIhvcNAQELBQAwYjELMAkGA1UEBhMCQlIxLTArBgNVBAoTJENlcnRpc2lnbiBDZXJ0aWZpY2Fkb3JhIERpZ2l0YWwgUy5BLjEkMCIGA1UEAxMbQUMgQ2VydGlTaWduIENvcnBvcmF0aXZhIEczMB4XDTI1MTEwOTAzMDAwMFoXDTI2MTEwOTAzMDAwMFowgYoxCzAJBgNVBAYTAkJSMS0wKwYDVQQKDCRDZXJ0aXNpZ24gQ2VydGlmaWNhZG9yYSBEaWdpdGFsIFMuQS4xHDAaBgNVBAMME1ZpY3RvciBZdWppIE1hZWhpcmExLjAsBgkqhkiG9w0BCQEWH3ZpY3Rvci5tYWVoaXJhQGNlcnRpc2lnbi5jb20uYnIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC38o1fQqrgsZz8AhWwCKxgDYE4ia0/sdMvqgHqT0G8n88TbRgZ2kMrc5e9ybVD+TlvmSaeN08EAx5NdB7mGJK/EGvRGlbKRIH0Soi9Eyv6Tvb9SDGod0OikK7YtS50rzkWQx2UVs7tQwOX139hlLXE8dfiL0KJ3/42hsKa/L1ZsoJBTXHleMScOFye1FdNgychP5ICJvWEo/Azz0CxZ9CITfRYpT7LVfFrQPWTGmdIIf7HOuO1YlTZ42gws3g05B5xTfq8KtSHzSIsRkscfmaZVP00o/o097f+gAU5jDC/t9ABDfHQT9PznIQWoR315/D+EVMsHVPbxGB4bg1pBBsvAgMBAAGjggELMIIBBzA6BgNVHREEMzAxoC8GCisGAQQBgjcUAgOgIQwfdmljdG9yLm1hZWhpcmFAY2VydGludHJhLmNvbS5icjAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFGFwXVXxIdM+YNQGfgQ/ME7pW2lDMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly9jZXJ0aXNpZ24tY2EuY2VydGlzaWduLmNvbS5ici9yZXBvc2l0b3Jpby9sY3IvQUNDZXJ0aXNpZ25Db3Jwb3JhdGl2YUczL0xhdGVzdENSTC5jcmwwDgYDVR0PAQH/BAQDAgXgMB8GA1UdJQQYMBYGCCsGAQUFBwMCBgorBgEEAYI3FAICMA0GCSqGSIb3DQEBCwUAA4ICAQCbrURiIPc+nIVatWYsyuZ631y/ziDamb3VzgQJf2gRY0qlAd/vFkanoTkaYRU0GEMeBbxh1Wk2eWUz85ptmr+lPFTYtb6CsVidpyP9QA9Pe6aWmd0vhxgUrWjIOLZmr2IVvmztsmqmWEMXkMU/I/LG3Y2oAJvzdHvieRMRspBw91Fc6mnUvce3OV0+xuqYrhya2dmOnrJx9kpvHPBeWri4qzik3XlpiG/VDvbfdeFnHg9NPbmsMR9hXjINSSHFEddJwaQZZhaL4T9GvEcibi7wAn5rbHyt85oOj0MF3vTqTbPm7TMChTT6HnlSZmzGOlVrUlkT6dxlYqUQvFAPDFQDodu1RKLaF/+KD9Jlsjm0e4QO8CstvIXA9QCQNqzrwoVFrg0Ob4d7WH733OjpiGsOmtRk2FKQfKKFpATTBwrfZ6bJjvKedOC9aD3i+GJoNvlbpTq6XopWci9L8T7NFBO6ubA6ZUkkwR1RMh+p0xXNP5fkWZL1djd0JYz1aO6MbCKspSIFlO+CaXe4gWgOg/GlJ4JgFWw0OEPaVxWzd75uW7XaE4WN/+EyBJ5dtf+4/5P53ZB6F/eAl6Ajan8yOnHPLReQLYMxGmvROBcEYcrysu3X0Oe6gPzJtLm/qdXso0V8tZSdajmy+i3hfQ55Xp67uxKeNxd+v/GimYvJg/33QQ=="
	
    init(smartCard: TKSmartCard, aid AID: Data?, tokenDriver: TKSmartCardTokenDriver) throws {
        let instanceID = "token_instance_id"
        super.init(smartCard: smartCard, aid: AID, instanceID: instanceID, tokenDriver: tokenDriver)
        let der = Self.mockCertificateDERBase64
            .filter { !$0.isWhitespace }
            .data(using: .utf8)
            .flatMap { Data(base64Encoded: $0) }
        guard let certData = der, let certRef = SecCertificateCreateWithData(nil, certData as CFData) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.corruptedData.rawValue, userInfo: [
                NSLocalizedDescriptionKey: "mock: DER inválido ou Base64 incorreto",
            ])
        }
        let certObjectID: TKToken.ObjectID = "mock-certificate-1"
        let keyObjectID: TKToken.ObjectID = "mock-signing-key-1"
        guard let certItem = TKTokenKeychainCertificate(certificate: certRef, objectID: certObjectID) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.corruptedData.rawValue, userInfo: [
            NSLocalizedDescriptionKey: "mock: não foi possível criar TKTokenKeychainCertificate",
            ])
        }
        certItem.label = "Certificado mock"

        guard let keyItem = TKTokenKeychainKey(certificate: certRef, objectID: keyObjectID) else {
            throw NSError(domain: TKErrorDomain, code: TKError.Code.corruptedData.rawValue, userInfo: [
                NSLocalizedDescriptionKey: "mock: não foi possível criar TKTokenKeychainKey",
            ])
        }
        keyItem.label = "Chave privada mock"
        keyItem.constraints = [
            NSNumber(value: TKTokenOperation.signData.rawValue): "PIN",
        ]
        let items: [TKTokenKeychainItem] = [certItem, keyItem]
                self.keychainContents!.fill(with: items)
    }
    func createSession(_ token: TKToken) throws -> TKTokenSession {
        TokenSession(token: self)
    }
}
