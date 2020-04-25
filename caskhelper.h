//
//  caskhelper.h
//  VirusCheckHBC
//
//  Created by CoreCode on 25/05/2019.
//  This file is licensed under the MIT license: https://opensource.org/licenses/MIT

@import Foundation;
#include "CoreLib.h"

@interface CaskHelper : NSObject

+ (NSString * _Nullable)getDownloadURLFromCaskfile:(NSString * _Nonnull)caskfileContents bundleIdentifier:(NSString * _Nonnull)bundleIdentifier;
+ (NSString * _Nonnull)getSHA256FromCaskfile:(NSString * _Nonnull)caskfileContents;

@end
