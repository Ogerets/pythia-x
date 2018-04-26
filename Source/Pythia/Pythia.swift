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

open class Pythia: NSObject {
    let proofKeys: ProofKeys
    let client: PythiaClientProtocol
    let accessTokenProvider: AccessTokenProvider
    let pythiaCrypto: PythiaCryptoProtocol // FIXME: This should be removed after Pythia crypto operations are available in VirgilCrypto
    
    init(params: PythiaContext, /*This should be removed. Use crypto packet*/ pythiaCrypto: PythiaCryptoProtocol) {
        self.proofKeys = params.proofKeys
        self.client = params.client
        self.accessTokenProvider = params.accessTokenProvider
        self.pythiaCrypto = pythiaCrypto
        
        super.init()
    }
    
    open func rotateSecret(updateToken: String, pythiaUser: PythiaUser) throws -> PythiaUser {
        let components = updateToken.components(separatedBy: ".")
        guard components.count == 4, components[0] == "UT",
            let prevVersion = UInt(components[1]),
            let nextVersion = UInt(components[2]),
            let updateTokenData = Data(base64Encoded: components[3]) else {
                throw NSError()  // Incorrect format
        }
        
        guard pythiaUser.version != nextVersion else {
            throw NSError() // Already migrated
        }
        
        guard pythiaUser.version == prevVersion else {
            throw NSError() // Wrong user version
        }
        
        let newDeblindedPassword = try self.pythiaCrypto.updateDeblindedWithToken(deblindedPassword: pythiaUser.deblindedPassword, updateToken: updateTokenData)
                
        return PythiaUser(salt: pythiaUser.salt, deblindedPassword: newDeblindedPassword, version: nextVersion)
    }
    
    open func register(password: String) -> GenericOperation<PythiaUser> {
        return CallbackOperation { _, completion in
            let salt: Data
            let blindedPassword: Data
            let blindingSecret: Data
            let latestProofKey: ProofKey
            do {
                salt = try self.pythiaCrypto.generateSalt()
                
                let blinded = try self.pythiaCrypto.blind(password: password)
                blindedPassword = blinded.0
                blindingSecret = blinded.1
                
                latestProofKey = try self.proofKeys.currentKey()
            }
            catch {
                completion(nil, error)
                return
            }
            
            let tokenContext = TokenContext(service: "pythia", operation: "transform", forceReload: false)
            let getTokenOperation = OperationUtils.makeGetTokenOperation(tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
            let transformOperation = self.makeTransformOperation(blindedPassword: blindedPassword, salt: salt, version: latestProofKey.version, prove: true)
            let verifyOperation = self.makeVerifyOperation(blindedPassword: blindedPassword, salt: salt, proofKey: latestProofKey.key)
            let finishRegistrationOperation = CallbackOperation<PythiaUser> { operation, completion in
                do {
                    let transformResponse: TransformResponse = try operation.findDependencyResult()
                    
                    let deblindedPassword = try self.pythiaCrypto.deblind(transformedPassword: transformResponse.transformedPassword, blindingSecret: blindingSecret)
                    
                    let registrationResponse = PythiaUser(salt: salt, deblindedPassword: deblindedPassword, version: latestProofKey.version)
                    
                    completion(registrationResponse, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
            
            let completionOperation = OperationUtils.makeCompletionOperation(completion: completion)
            
            transformOperation.addDependency(getTokenOperation)
            
            verifyOperation.addDependency(transformOperation)
            finishRegistrationOperation.addDependency(transformOperation)
            
            completionOperation.addDependency(getTokenOperation)
            completionOperation.addDependency(transformOperation)
            completionOperation.addDependency(verifyOperation)
            completionOperation.addDependency(finishRegistrationOperation)
            
            let queue = OperationQueue()
            let operations = [getTokenOperation, transformOperation, verifyOperation, finishRegistrationOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }
    
    open func authenticate(password: String, pythiaUser: PythiaUser, prove: Bool) -> GenericOperation<Bool> {
        return CallbackOperation { _, completion in
            let tokenContext = TokenContext(service: "pythia", operation: "transform", forceReload: false)
            let getTokenOperation = OperationUtils.makeGetTokenOperation(tokenContext: tokenContext, accessTokenProvider: self.accessTokenProvider)
            
            let blindedPassword: Data
            let blindingSecret: Data
            let proofKey: Data
            do {
                let blinded = try self.pythiaCrypto.blind(password: password)
                blindedPassword = blinded.0
                blindingSecret = blinded.1
                
                proofKey = try self.proofKeys.proofKey(forVersion: pythiaUser.version)
            }
            catch {
                completion(nil, error)
                return
            }
            
            let transformPasswordOperation = self.makeTransformOperation(blindedPassword: blindedPassword, salt: pythiaUser.salt, version: pythiaUser.version, prove: prove)
            
            let verifyOperation: GenericOperation<Bool>
            if prove {
                verifyOperation = self.makeVerifyOperation(blindedPassword: blindedPassword, salt: pythiaUser.salt, proofKey: proofKey)
            }
            else {
                verifyOperation = CallbackOperation { _, completion in
                    completion(true, nil)
                }
            }
            
            let authOperation = CallbackOperation<Bool> { operation, completion in
                do {
                    let transformResponse: TransformResponse = try operation.findDependencyResult()
                    
                    let deblindedPassowrd = try self.pythiaCrypto.deblind(transformedPassword: transformResponse.transformedPassword, blindingSecret: blindingSecret)
                    
                    guard deblindedPassowrd == pythiaUser.deblindedPassword else {
                        completion(false, nil)
                        return
                    }
                    
                    completion(true, nil)
                }
                catch {
                    completion(nil, error)
                }
            }
            
            let completionOperation = CallbackOperation { _, completion in
                completion(Void(), nil)
            }
            
            completionOperation.completionBlock = {
                guard let proofResult = verifyOperation.result,
                    let authResult = authOperation.result,
                    case let .success(proof) = proofResult, proof,
                    case let .success(auth) = authResult, auth else {
                        completion(false, nil)
                        return
                }
                
                completion(true, nil)
            }
            
            transformPasswordOperation.addDependency(getTokenOperation)
            
            authOperation.addDependency(transformPasswordOperation)
            verifyOperation.addDependency(transformPasswordOperation)
            
            completionOperation.addDependency(getTokenOperation)
            completionOperation.addDependency(transformPasswordOperation)
            completionOperation.addDependency(verifyOperation)
            completionOperation.addDependency(authOperation)
            
            let queue = OperationQueue()
            let operations = [getTokenOperation, transformPasswordOperation, verifyOperation, authOperation, completionOperation]
            queue.addOperations(operations, waitUntilFinished: false)
        }
    }
}
