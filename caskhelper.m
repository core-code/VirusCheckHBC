//
//  caskhelper.m
//  VirusCheckHBC
//
//  Created by CoreCode on 25/05/2019.
//  This file is licensed under the GPLv2 license: https://opensource.org/licenses/GPL-2.0

@import Foundation;
#include "caskhelper.h"


@implementation CaskHelper

+ (NSString *)getSHA256FromCaskfile:(NSString *)caskfileContents
{
    if ([caskfileContents contains:@"sha256 :no_check"]) return @":no_check";
    
    let shaLines = [caskfileContents.lines filtered:^BOOL(NSString *input) { return [input.trimmedOfWhitespace hasPrefix:@"sha256 '"]; }];
    var shaLine = shaLines.lastObject;
    
    shaLine = [shaLine.trimmedOfWhitespace removed:@"sha256 "].trimmedOfWhitespace;
    shaLine = [shaLine substringWithRange:NSMakeRange(1, shaLine.length-2)]; // remove quotes
    
    return shaLine;
}

+ (NSString *)_getRubyURLFromCaskfile:(NSString *)caskfileContents
{
    //versions
    caskfileContents = [caskfileContents replaced:@":snow_leopard" with:@"6"];
    caskfileContents = [caskfileContents replaced:@":lion" with:@"7"];
    caskfileContents = [caskfileContents replaced:@":mountain_lion" with:@"8"];
    caskfileContents = [caskfileContents replaced:@":mavericks" with:@"9"];
    caskfileContents = [caskfileContents replaced:@":yosemite" with:@"10"];
    caskfileContents = [caskfileContents replaced:@":el_capitan" with:@"11"];
    caskfileContents = [caskfileContents replaced:@":sierra" with:@"12"];
    caskfileContents = [caskfileContents replaced:@":high_sierra" with:@"13"];
    caskfileContents = [caskfileContents replaced:@":mojave" with:@"14"];
    caskfileContents = [caskfileContents replaced:@":catalina" with:@"15"];

    NSArray <NSString *> *lines = caskfileContents.lines;
    NSMutableArray *result = makeMutableArray();
    
    for (NSString *line in lines)
        if ([line contains:@"url '"] || [line contains:@"url \""] || [line contains:@"if MacOS"] || [line contains:@"elsif MacOS"])
            [result addObject:[line hasSuffix:@","] ? [line slicingSubstringToIndex:-1] : line.trimmedOfWhitespace]; // some end with a "," as they have a user_agent
    
    [result insertObject:@"else" atIndex:result.count-1];
    [result addObject:@"end"];
    
    let ourOS = NSProcessInfo.processInfo.operatingSystemVersion;

    NSString *finalScript = [[[[result.joinedWithNewlines  replaced:@"url '" with:@"    puts '"]   replaced:@"url \"" with:@"    puts \""] replaced:@"#{" with:@"…"] replaced:@"MacOS.version" with:@(ourOS.minorVersion).stringValue];
    NSString *path = makeTempFilepath(@"rb");
    if (!path)
    {
        cc_log_error(@"Error: makeTempFilepath failed error");
        return nil;
    }
    [finalScript writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    NSString *output;
    
    @try
    {
        output = [@[@"/usr/bin/ruby", @"-W0",path] runAsTaskWithTerminationStatus:NULL usePolling:NO];
        if (!output)
        {   // this will fail rarely on systems where spawn doesn't work
            cc_log_error(@"Error: _getRubyURLFromCaskfile did get nil output");
        }
    }
    @catch (id)
    {
        cc_log_error(@"Error: _getRubyURLFromCaskfile did get exception");
    }
    

    [fileManager removeItemAtPath:path error:NULL];
    [fileManager removeItemAtPath:path.stringByDeletingLastPathComponent error:NULL];
    
    if ([output contains:@"syntax error"])
    {
        // if the whole thing didn't work we probably don't have a url distinction based on macos, but based on language, just take the default one
        if ([caskfileContents contains:@"default: true do"])
        {
            NSString *newString = [caskfileContents split:@"default: true do"][1];
            
            let urlLines = [newString.lines filtered:^BOOL(NSString *input) { return [input.trimmedOfWhitespace hasPrefix:@"url "]; }];
            assert(urlLines.count);
            if (!urlLines.count)
            {
                cc_log_error(@"Error: _getRubyURLFromCaskfile did get syntax error");
                return nil;
            }
            return urlLines.firstObject;
        }
        else
        {
            cc_log_error(@"Error: _getRubyURLFromCaskfile did get syntax error");
            return nil;
        }
    }
    else
    {
        output = [output replaced:@"…" with:@"#{"];

        return makeString(@"url '%@'", output.trimmedOfWhitespaceAndNewlines);
    }
}

+ (NSString *)_getRubyVersionFromCaskfile:(NSString *)caskfileContents
{
    //versions
    caskfileContents = [caskfileContents replaced:@":tiger" with:@"4"];
    caskfileContents = [caskfileContents replaced:@":leopard" with:@"5"];
    caskfileContents = [caskfileContents replaced:@":snow_leopard" with:@"6"];
    caskfileContents = [caskfileContents replaced:@":lion" with:@"7"];
    caskfileContents = [caskfileContents replaced:@":mountain_lion" with:@"8"];
    caskfileContents = [caskfileContents replaced:@":mavericks" with:@"9"];
    caskfileContents = [caskfileContents replaced:@":yosemite" with:@"10"];
    caskfileContents = [caskfileContents replaced:@":el_capitan" with:@"11"];
    caskfileContents = [caskfileContents replaced:@":sierra" with:@"12"];
    caskfileContents = [caskfileContents replaced:@":high_sierra" with:@"13"];
    caskfileContents = [caskfileContents replaced:@":mojave" with:@"14"];
    caskfileContents = [caskfileContents replaced:@":catalina" with:@"15"];

    NSArray <NSString *> *lines = caskfileContents.lines;
    NSMutableArray *result = makeMutableArray();
    
    for (NSString *line in lines)
    {
        if ([line contains:@"version "] || [line contains:@"if MacOS"] || [line contains:@"elsif MacOS"])
            [result addObject:line.trimmedOfWhitespace];
        else if (result.count && [line isEqualToString:@"  end"])
            break;
    }
    [result insertObject:@"else" atIndex:result.count-1];
    [result addObject:@"end"];
    
    let ourOS = NSProcessInfo.processInfo.operatingSystemVersion;
    NSString *finalScript = result.joinedWithNewlines;
    finalScript = [finalScript replaced:@":latest" with:@"':latest'"];
    finalScript = [finalScript replaced:@"version '" with:@"    puts '"];
    finalScript = [finalScript replaced:@"MacOS.version" with:@(ourOS.minorVersion).stringValue];
    
    NSString *path = makeTempFilepath(@"rb");
    if (!path)
    {
        cc_log_error(@"Error: makeTempFilepath failed error");
        return nil;
    }
    
    NSError *writeError;
    BOOL writeSucc = [finalScript writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError];
    if (!writeSucc)
    {
        cc_log_error(@"Error: writeToFile failed error: %@", writeError.description);
        return nil;
    }
    NSString *output;
    
    @try
    {
        output = [@[@"/usr/bin/ruby", @"-W0", path] runAsTaskWithTerminationStatus:NULL usePolling:NO];
        if (!output)
        {   // this will fail rarely on systems where spawn doesn't work
            cc_log_error(@"Error: _getRubyVersionsFromCaskfile did get nil output");
        }
    }
    @catch (id)
    {
        cc_log_error(@"Error: _getRubyVersionsFromCaskfile did get exception");
    }
    
    if ([output.lowercaseString contains:@"error"])
        cc_log_error(@"Error: failure %@", output);

    [fileManager removeItemAtPath:path error:NULL];
    [fileManager removeItemAtPath:path.stringByDeletingLastPathComponent error:NULL];

    
    let versionString = output.trimmedOfWhitespaceAndNewlines;
    return versionString.length ?  makeString(@"version '%@'", versionString) : nil;
}

+ (NSString *)getVersionFromCaskfile:(NSString *)caskfileContents
{
    let versionLines = [caskfileContents.lines filtered:^BOOL(NSString *input) { return [input.trimmedOfWhitespace hasPrefix:@"version "]; }];
    var versionLine = @"";
    
    if (versionLines.count == 0)
        return nil;
    else if (versionLines.count == 1)
        versionLine = versionLines.firstObject;
    else
    {
        versionLine = [self _getRubyVersionFromCaskfile:caskfileContents];
        if (!versionLine)  versionLine = versionLines.lastObject;
    }
    
    if ([versionLine contains:@":latest"])
        return @":latest";
    
    versionLine = [versionLine.trimmedOfWhitespace removed:@"version "].trimmedOfWhitespace;
    versionLine = [versionLine substringWithRange:NSMakeRange(1, versionLine.length-2)];
        
    return versionLine;
}

+ (NSString *)getUnprocessedDownloadURLFromCaskfile:(NSString *)caskfileContents
{
    let urlLines = [caskfileContents.lines filtered:^BOOL(NSString *input) { return [input.trimmedOfWhitespace hasPrefix:@"url "]; }];
    if (caskfileContents) // this can be empty if updateAppViaCask uses sparkle
    {
        assert(urlLines.count);
    }
    
    var urlLine = @"";

    if (urlLines.count == 0)
        return nil;
    else if (urlLines.count == 1)
        urlLine = urlLines.firstObject;
    else
        urlLine = [self _getRubyURLFromCaskfile:caskfileContents];
    
    urlLine = [urlLine.trimmedOfWhitespace removed:@"url "].trimmedOfWhitespace;
    
    if ([urlLine hasSuffix:@"\","] || ([urlLine hasSuffix:@"\',"]))
        urlLine = [urlLine substringWithRange:NSMakeRange(0, urlLine.length-1)]; // some end with a "," as they have a user_agent
    
    urlLine = [urlLine substringWithRange:NSMakeRange(1, urlLine.length-2)]; // remove quotes ... we don't know which quotes, just strip first and last char
    
    return urlLine;
}

+ (NSString *)_replaceVersionInURL:(NSString *)urlLine version:(NSString *)version
{
    NSString *finalURL = urlLine;
    
    if ([finalURL contains:@"#{version}"])
        finalURL = [finalURL replaced:@"#{version}" with:version];
    
    if (![finalURL contains:@"#{"]) return finalURL; // early out for common case
    
    
    if ([finalURL contains:@"#{version.before_comma.dots_to_underscores}"])
        finalURL = [finalURL replaced:@"#{version.before_comma.dots_to_underscores}" with:[[version split:@","][0] replaced:@"." with:@"_"]];
    if ([finalURL contains:@"#{version.before_comma.no_dots}"])
        finalURL = [finalURL replaced:@"#{version.before_comma.no_dots}" with:[[version split:@","][0] removed:@"."]];
    if ([finalURL contains:@"#{version.major_minor.no_dots}"])
        finalURL = [finalURL replaced:@"#{version.major_minor.no_dots}" with:makeString(@"%@%@",
                                                                                        [version split:@"."][0],
                                                                                        OBJECT_OR([[version split:@"."] safeObjectAtIndex:1], @""))];
    if ([finalURL contains:@"#{version.dots_to_hyphens}"])
        finalURL = [finalURL replaced:@"#{version.dots_to_hyphens}" with:[version replaced:@"." with:@"-"]];
    if ([finalURL contains:@"#{version.major_minor_patch}"])
    {
        let dotcomponents = [version split:@"."];
        var majorminorpatch = dotcomponents[0];
        
        if (dotcomponents.count > 1)
        {
            majorminorpatch = [majorminorpatch stringByAppendingString:@"."];
            majorminorpatch = [majorminorpatch stringByAppendingString:dotcomponents[1]];
        }
        if (dotcomponents.count > 2)
        {
            majorminorpatch = [majorminorpatch stringByAppendingString:@"."];
            majorminorpatch = [majorminorpatch stringByAppendingString:dotcomponents[2]];
        }
        finalURL = [finalURL replaced:@"#{version.major_minor_patch}" with:majorminorpatch];
    }
    if ([finalURL contains:@"#{version.after_comma.before_colon}"])
        finalURL = [finalURL replaced:@"#{version.after_comma.before_colon}" with:[[[version split:@","] safeObjectAtIndex:1] split:@":"][0]];
    if ([finalURL contains:@"#{version.major_minor}"])
    {
        let dotcomponents = [version split:@"."];
        var majorminor = dotcomponents[0];
        
        if (dotcomponents.count > 1)
        {
            majorminor = [majorminor stringByAppendingString:@"."];
            majorminor = [majorminor stringByAppendingString:dotcomponents[1]];
        }
        finalURL = [finalURL replaced:@"#{version.major_minor}" with:majorminor];
    }
    if ([finalURL contains:@"#{version.dots_to_underscores}"])
        finalURL = [finalURL replaced:@"#{version.dots_to_underscores}" with:[version replaced:@"." with:@"_"]];
    if ([finalURL contains:@"#{version.after_comma}"])
        finalURL = [finalURL replaced:@"#{version.after_comma}" with:[[version split:@","] safeObjectAtIndex:1]];
    if ([finalURL contains:@"#{version.after_comma.dots_to_slashes}"])
        finalURL = [finalURL replaced:@"#{version.after_comma.dots_to_slashes}" with:[[[version split:@","] safeObjectAtIndex:1] replaced:@"." with:@"/"]];
    if ([finalURL contains:@"#{version.before_comma}"])
        finalURL = [finalURL replaced:@"#{version.before_comma}" with:[version split:@","][0]];
    if ([finalURL contains:@"#{version.after_colon}"])
        finalURL = [finalURL replaced:@"#{version.after_colon}" with:[[version split:@":"] safeObjectAtIndex:1]];
    if ([finalURL contains:@"#{version.major}"])
        finalURL = [finalURL replaced:@"#{version.major}" with:[version split:@"."][0]];
    if ([finalURL contains:@"#{version.minor}"])
        finalURL = [finalURL replaced:@"#{version.minor}" with:[[version split:@"."] safeObjectAtIndex:1]];
    if ([finalURL contains:@"#{version.patch}"])
        finalURL = [finalURL replaced:@"#{version.patch}" with:[[version split:@"."] safeObjectAtIndex:2]];
    if ([finalURL contains:@"#{version.no_dots}"])
        finalURL = [finalURL replaced:@"#{version.no_dots}" with:[version removed:@"."]];
    
    if ([finalURL contains:@"#{version.split('.').last}"])
        finalURL = [finalURL replaced:@"#{version.split('.').last}" with:[version split:@"."].lastObject];

    if ([finalURL contains:@"#{version.after_comma.major}"])
        finalURL = [finalURL replaced:@"#{version.after_comma.major}" with:[[[version split:@","] safeObjectAtIndex:1] split:@"."].firstObject];

    return finalURL;
}

+ (NSString *)getDownloadURLFromCaskfile:(NSString *)caskfileContents bundleIdentifier:(NSString *)bundleIdentifier
{
    let urlLine = [CaskHelper getUnprocessedDownloadURLFromCaskfile:caskfileContents];

    var downloadURL = @"";

    if (![urlLine contains:@"#{"]) // no need to parse URL, just extract it
    {
        downloadURL = urlLine;
    }
    else
    {
        let version = [CaskHelper getVersionFromCaskfile:caskfileContents];
        
        if (!version)
        {
            cc_log_error(@"Error: caskfile does not seem to contain any version lines %@", bundleIdentifier);
            return nil;
        }
        


        if (![[urlLine stringByReplacingMultipleStrings:@{@"#{version.before_comma.dots_to_underscores}" : @"",
                                                          @"#{version.major_minor.no_dots}" : @"",
                                                          @"#{version.dots_to_hyphens}" : @"",
                                                          @"#{version.major_minor_patch}" : @"",
                                                          @"#{version.after_comma.before_colon}" : @"",
                                                          @"#{version.major_minor}" : @"",
                                                          @"#{version.dots_to_underscores}" : @"",
                                                          @"#{version.after_comma}" : @"",
                                                          @"#{version.before_comma}" : @"",
                                                          @"#{version.major}" : @"",
                                                          @"#{version.major}" : @"",
                                                          @"#{version.minor}" : @"",
                                                          @"#{version.patch}" : @"",
                                                          @"#{version.after_comma.dots_to_slashes}" : @"",
                                                          @"#{version.before_comma.no_dots}" : @"",
                                                          @"#{version.after_colon}" : @"",
                                                          @"#{version.no_dots}" : @"",
                                                          @"#{version}" : @""}] contains:@"#{"])
        {
            NSString * finalURL = [self _replaceVersionInURL:urlLine version:version];
            
            downloadURL = finalURL;
        }
        else
        {
            NSString *language = @"en-US";
            
    #if defined(CLI) && !defined(WEBSITEINSTALLHELPER)
            let convertRubyScriptPath = makeString(@"%@/MacUpdater/MacUpdater/Ruby/convertCaskDownloadURL.rb", NSProcessInfo.processInfo.environment[@"CC_APP_PATH"]);
    #else
            let convertRubyScriptPath = @"convertCaskDownloadURL.rb".resourcePath;
    #endif
            NSString *output;
            NSInteger status;
            @try
            {
                output = [@[@"/usr/bin/ruby", @"-W0", convertRubyScriptPath, version, urlLine, language] runAsTaskWithTerminationStatus:&status usePolling:NO];
            }
            @catch (NSException *exception)
            {
                NSString *exceptionInfo = exception.description;
                cc_log_error(@"Error: could not convert download url using convert ruby script because of an exception %@ %@", exceptionInfo, bundleIdentifier);
                return nil;
            }
            
            
            if (!output) // this will (only) be hit if there are problems on the system that e.g. prevent posix_spawn
            {
                cc_log_error(@"Error: could not convert download url using convert ruby script empty result %@", bundleIdentifier);
                return nil;
            }
            if (status)
            {
                cc_log_error(@"Error: could not convert download url using convert ruby script non-null status code %li %@ %@", (long)status, bundleIdentifier, output);
                return nil;
            }
            
            downloadURL = output.trimmedOfWhitespaceAndNewlines;
        }

        if (!([downloadURL hasPrefix:@"http"] || [downloadURL hasPrefix:@"ftp"]))
        {
            cc_log_error(@"Error: could not convert download url using convert ruby script invalid download url format %@ %@", downloadURL, bundleIdentifier);
            return nil;
        }
    }
    
    return downloadURL;
}

@end
