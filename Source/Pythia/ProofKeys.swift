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

struct ProofKeys {
    let proofKeys: [ProofKey]
    
    private static func parsePublicKey(_ string: String) throws -> ProofKey {
        let components = string.components(separatedBy: ".")
        guard components.count == 3, components[0] == "PK",
            let version = UInt(components[1]),
            let data = Data(base64Encoded: components[2]) else {
                throw NSError() // Incorrect format
        }
        
        return ProofKey(key: data, version: version)
    }
    
    init(proofKeys: [String]) throws {
        guard proofKeys.count > 0 else {
            throw NSError()
        }
        
        self.proofKeys = try proofKeys.map({ try ProofKeys.parsePublicKey($0) }).sorted(by: { $0.version > $1.version })
    }
    
    func currentKey() throws -> ProofKey {
        guard let proofKey = self.proofKeys.first else {
            // Something very bad has happened. Probably, unsuccessful migration
            throw NSError()
        }
        
        return proofKey
    }
    
    func proofKey(forVersion version: UInt) throws -> Data {
        guard let key = self.proofKeys.first(where: { $0.version == version })?.key else {
            // Something very bad has happened. Probably, unsuccessful migration
            throw NSError()
        }
        
        return key
    }
}
