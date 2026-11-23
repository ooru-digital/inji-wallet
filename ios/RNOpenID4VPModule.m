#import <Foundation/Foundation.h>
#import "React/RCTBridgeModule.h"
#import <React/RCTEventEmitter.h>

// RCTEventEmitter, not NSObject: it supplies the addListener/removeListeners pair that
// NativeEventEmitter requires on iOS. See the comment in RNOpenID4VPModule.swift.
@interface RCT_EXTERN_MODULE(InjiOpenID4VP, RCTEventEmitter)

RCT_EXTERN_METHOD(initSdk:(NSString *)appId
                  walletConfig:(id)walletConfig)

RCT_EXTERN_METHOD(authenticateVerifier:(NSString *)urlEncodedAuthorizationRequest
                  trustedVerifiers:(id)trustedVerifiers
                  shouldValidateClient:(BOOL)shouldValidateClient
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(getMatchingCredentials:(id)vpRequest
                  availableWalletCredentials:(id)availableWalletCredentials
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(constructUnsignedVPToken:(id)selectedVCs
                  fallbackHolderId:(NSString *)fallbackHolderId
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(shareVerifiablePresentation:(NSArray *)vpTokenSigningResults
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(sendErrorToVerifier:(NSString *)error
                  :(NSString *)errorCode
                  resolver:(RCTPromiseResolveBlock)resolve
                  rejecter:(RCTPromiseRejectBlock)reject)

// JSON-LD results from JS, in response to onJsonLdCanonicalize / onJsonLdExpand
RCT_EXTERN_METHOD(sendJsonLdCanonicalizeResultFromJS:(NSString *)result)
RCT_EXTERN_METHOD(notifyCanonicalizationFailureFromJS:(NSString *)code
                  message:(NSString *)message)
RCT_EXTERN_METHOD(sendJsonLdExpandResultFromJS:(id)result)
RCT_EXTERN_METHOD(notifyJsonLdExpansionFailureFromJS:(NSString *)code
                  message:(NSString *)message)

@end
