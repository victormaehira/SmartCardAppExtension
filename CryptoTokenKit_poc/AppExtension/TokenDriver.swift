//
//  TokenDriver.swift
//  AppExtension
//
//  Created by Victor Yuji Maehira on 23/03/26.
//

import CryptoTokenKit

class TokenDriver: TKSmartCardTokenDriver, TKSmartCardTokenDriverDelegate {

    func tokenDriver(_ driver: TKSmartCardTokenDriver, createTokenFor smartCard: TKSmartCard, aid AID: Data?) throws -> TKSmartCardToken {
        return try Token(smartCard: smartCard, aid: AID, tokenDriver: self)
    }

}
