//
// Copyright (C) 2015-2018 Virgil Security Inc.
//
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     (1) Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//     (2) Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//
//     (3) Neither the name of the copyright holder nor the names of its
//     contributors may be used to endorse or promote products derived from
//     this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
//

import Foundation
import VirgilSDK
import VirgilCryptoApiImpl

struct PythiaParams {
    let proofKeys: ProofKeys
    let client: PythiaClientProtocol
    let accessTokenProvider: AccessTokenProvider
    
    static func makeParams(apiKey: String, apiPublicKeyIdentifier: String, appId: String, proofKeys: [String]) throws -> PythiaParams {
        let client = PythiaClient()
        
        guard let apiKeyData = Data(base64Encoded: apiKey) else {
            throw NSError()
        }
        
        let apiPrivateKey = try VirgilCrypto().importPrivateKey(from: apiKeyData)
        
        let generator = JwtGenerator(apiKey: apiPrivateKey, apiPublicKeyIdentifier: apiPublicKeyIdentifier, accessTokenSigner: VirgilAccessTokenSigner(virgilCrypto: VirgilCrypto()), appId: appId, ttl: /* 1 hour */ 60 * 60)
        
        let accessTokenProvider = CachingJwtProvider(renewJwtCallback: { tokenContext, completion in
            do {
                let token = try generator.generateToken(identity: "PYTHIA-CLIENT")
                completion(token, nil)
            }
            catch {
                completion(nil, error)
            }
        })
        
        let proofKeys = try ProofKeys(proofKeys: proofKeys)
        
        return PythiaParams(proofKeys: proofKeys, client: client, accessTokenProvider: accessTokenProvider)
    }
}
