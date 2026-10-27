#import <Foundation/Foundation.h>
#import "React/RCTBridgeModule.h"

@interface RCT_EXTERN_MODULE(SnapKycLivenessModule, NSObject)

RCT_EXTERN_METHOD(startLiveness:(NSDictionary *)config
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(matchFace:(NSString *)probeBase64
                  galleryBase64:(NSString *)galleryBase64
                  resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject)

RCT_EXTERN_METHOD(closeFaceMatch)

@end
