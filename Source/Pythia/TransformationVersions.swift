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

struct TransformationVersions {
    let publicKey: (Int, Data)
    let oldPublicKey: (Int, Data)?
    
    private static func parsePublicKey(_ string: String) throws -> (Int, Data) {
        let components = string.components(separatedBy: ".")
        guard components.count == 2 else {
            throw NSError()
        }
        
        guard let version = Int(components[0]) else {
            throw NSError()
        }
        
        guard let data = Data(base64Encoded: components[1]) else {
            throw NSError()
        }
        
        return (version, data)
    }
    
    init(publicKey: String, oldPublicKey: String? = nil) throws {
        self.publicKey = try TransformationVersions.parsePublicKey(publicKey)
        
        if let oldTrKey = oldPublicKey {
            self.oldPublicKey = try TransformationVersions.parsePublicKey(oldTrKey)
        }
        else {
            self.oldPublicKey = nil
        }
    }
    
    func publicKey(forVersion version: Int) throws -> Data {
        if version == self.publicKey.0 {
            return self.publicKey.1
        }
        
        if let old = self.oldPublicKey, version == old.0 {
            return old.1
        }
        
        // Something very bad has happened. Probably, unsuccessful migration
        throw NSError()
    }
}
