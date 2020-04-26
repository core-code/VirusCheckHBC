//
//  main.m
//  VirusCheckHBC
//
//  Created by CoreCode on 25/05/2019.
//  This file is licensed under the MIT license: https://opensource.org/licenses/MIT

@import Foundation;
#include "CoreLib.h"
#include "caskhelper.h"

NSString *apiKey;

BOOL hasVirus(NSDictionary *virusTotalAnswer)
{
    NSArray *goodScanners = @[@"Avast",@"AVG",@"Avira",@"BitDefender",@"ClamAV",@"Emsisoft",@"ESET-NOD32",@"F-Secure",@"GData",@"Sophos",@"Symantec"];

    NSDictionary *scans = virusTotalAnswer[@"scans"];
    for (NSString *scanner in goodScanners)
    {
        NSDictionary *answer = scans[scanner];
        
        if ([answer[@"detected"] intValue])
            return YES;
    }
    return NO;
}

void checkVirusTotal(NSArray *caskFiles)
{
    let checkedURLs = makeMutableDictionary();
    let queuedURLs = makeMutableArray();
    let queuedResourcesToRescan = makeMutableSet();
    let df = NSDateFormatter.new;
    df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
    df.locale = [[NSLocale alloc] initWithLocaleIdentifier:@"en_US_POSIX"];
    
    int i = 0;
    
    
    for (NSString *caskFile in caskFiles)
    {
        @autoreleasepool
        {
            let caskName = caskFile.lastPathComponent.stringByDeletingPathExtension;
            let caskfileContents = caskFile.fileURL.contents.stringUTF8;
            let sha = [CaskHelper getSHA256FromCaskfile:caskfileContents];
            let downloadURL = [CaskHelper getDownloadURLFromCaskfile:caskfileContents bundleIdentifier:@""];

            
            if (sha && ![sha contains:@":no_check"])
            {
                let url = makeString(@"https://www.virustotal.com/vtapi/v2/file/report?apikey=%@&resource=%@", apiKey, sha);
                
                let resp = url.download.string;
                let dict = resp.data.JSONDictionary;
               
                
                if (dict[@"resource"] && dict[@"scan_date"] && ![[NSNull null] isEqual:dict[@"scan_date"]] && [df dateFromString:dict[@"scan_date"]] && [NSDate.date timeIntervalSinceDate:[df dateFromString:dict[@"scan_date"]]] > SECONDS_PER_WEEKS(8))
                    [queuedResourcesToRescan addObject:dict[@"resource"]];
                
                if (hasVirus(dict))
                    cc_log_emerg(@"VIRUSERROR: cSHA POSITIVES %i %@ %@", [dict[@"positives"] intValue], caskName, resp);
                else if ([dict[@"verbose_msg"] contains:@"is not among the"])
                    cc_log(@"Warning: cSHA unknown %@", caskName);
                else if (dict[@"response_code"] && [dict[@"response_code"] intValue] == 1)
                    cc_log(@"Info: cSHA OK %@", caskName);
                else if ([dict[@"verbose_msg"] contains:@"is queued for analysis"])
                    cc_log(@"Warning: cSHA queued for analysis %@ - will be checked in next run", caskName); // ideally we'd re-scan them at the end just like the queued URLs
                else
                    cc_log_error(@"ERROR: cSHA unknown response: %@ %@", caskName, resp);


                if (dict[@"positives"])
                    checkedURLs[downloadURL] = @(1);

                
                [NSThread sleepForTimeInterval:16.0];
            }
            
            
            
            if (downloadURL && !checkedURLs[downloadURL])
            {
                let url = makeString(@"https://www.virustotal.com/vtapi/v2/url/report?apikey=%@&scan=1&resource=%@", apiKey, downloadURL);

                let resp = url.download.string;
                let dict = resp.data.JSONDictionary;
                BOOL checked = NO;
                
                if (dict[@"resource"] && dict[@"scan_date"] && ![[NSNull null] isEqual:dict[@"scan_date"]] && [df dateFromString:dict[@"scan_date"]] && [NSDate.date timeIntervalSinceDate:[df dateFromString:dict[@"scan_date"]]] > SECONDS_PER_WEEKS(8))
                    [queuedResourcesToRescan addObject:dict[@"resource"]];
                
                if ([dict[@"verbose_msg"] contains:@"successfully queued"])
                {
                    cc_log(@"Info: cURL queued %@ - retrying later", caskName);
                    downloadURL.associatedValue = caskName;
                    [queuedURLs addObject:downloadURL];
                    checked = YES;
                }
                else if (dict[@"filescan_id"] && ![[NSNull null] isEqual:dict[@"filescan_id"]])
                {
                    [NSThread sleepForTimeInterval:16.0];

                    
                    let url = makeString(@"https://www.virustotal.com/vtapi/v2/file/report?apikey=%@&resource=%@", apiKey, dict[@"filescan_id"]);
                    
                    let resp = url.download.string;
                    let dict = resp.data.JSONDictionary;
                    
                    if (dict[@"resource"] && dict[@"scan_date"] && ![[NSNull null] isEqual:dict[@"scan_date"]] && [df dateFromString:dict[@"scan_date"]] && [NSDate.date timeIntervalSinceDate:[df dateFromString:dict[@"scan_date"]]] > SECONDS_PER_WEEKS(8))
                        [queuedResourcesToRescan addObject:dict[@"resource"]];
                    
                    if (hasVirus(dict))
                        cc_log_emerg(@"VIRUSERROR: cFUR POSITIVES %i %@ %@", [dict[@"positives"] intValue], caskName, resp);
                    else if ([dict[@"verbose_msg"] contains:@"is not among the"])
                        cc_log(@"Warning: cFUR unknown %@", caskName);
                    else if (dict[@"response_code"] && [dict[@"response_code"] intValue] == 1)
                        cc_log(@"Info: cFUR OK %@", caskName);
                    else
                        cc_log_error(@"ERROR: cFUR unknown response: %@ %@", caskName, resp);

                    if (dict[@"positives"])
                        checked = YES;
                }
                
                if (hasVirus(dict))
                    cc_log(@"VIRUSWARNING: cURL POSITIVES %i %@ %@", [dict[@"positives"] intValue], caskName, resp);
                else if (!checked && (dict[@"response_code"] && [dict[@"response_code"] intValue] == 1))
                    cc_log(@"Info: cURL OK %@", caskName);
                else if (!checked)
                    cc_log(@"ERROR: cURL unknown response: %@ %@", caskName, resp);
                
                checkedURLs[downloadURL] = @(1);

                [NSThread sleepForTimeInterval:16.0];
            }
           
            if (++i % 100 == 0)
                cc_log(@"\nInfo: checked %i of %lu apps\n", i, (unsigned long)caskFiles.count);
        }
    }
    cc_log(@"\nInfo: now checking %lu queued URLs\n", (unsigned long)queuedURLs.count);

    for (NSString *downloadURL in queuedURLs)
    {
        let url = makeString(@"https://www.virustotal.com/vtapi/v2/url/report?apikey=%@&scan=1&resource=%@", apiKey, downloadURL);
        
        let resp = url.download.string;
        let dict = resp.data.JSONDictionary;
        BOOL checked = NO;
        
        if ([dict[@"verbose_msg"] contains:@"successfully queued"] || [dict[@"verbose_msg"] contains:@"queued for analysis"])
        {
            cc_log_error(@"Error: qURL queued %@", downloadURL);
            checked = YES;
        }
        else if (dict[@"filescan_id"] && ![[NSNull null] isEqual:dict[@"filescan_id"]])
        {
            [NSThread sleepForTimeInterval:16.0];
            
            
            let url = makeString(@"https://www.virustotal.com/vtapi/v2/file/report?apikey=%@&resource=%@", apiKey, dict[@"filescan_id"]);
            
            let resp = url.download.string;
            let dict = resp.data.JSONDictionary;
            
            
            if (hasVirus(dict))
                cc_log_emerg(@"VIRUSERROR: qFUR POSITIVES %i %@ %@ %@", [dict[@"positives"] intValue], downloadURL, downloadURL.associatedValue, resp);
            else if ([dict[@"verbose_msg"] contains:@"is not among the"])
                cc_log(@"Warning: qFUR unknown %@", downloadURL);
            else if (dict[@"response_code"] && [dict[@"response_code"] intValue] == 1)
                cc_log(@"Info: qFUR OK %@ %@", downloadURL, downloadURL.associatedValue);
            else
                cc_log_error(@"ERROR: qFUR unknown response: %@ %@", downloadURL, resp);
            
            if (dict[@"positives"])
                checked = YES;
        }
        
        if (!checked && hasVirus(dict))
            cc_log(@"VIRUSWARNING: qURL POSITIVES %i %@ %@ %@", [dict[@"positives"] intValue], downloadURL, downloadURL.associatedValue, resp);
        else if (!checked && (dict[@"response_code"] && [dict[@"response_code"] intValue] == 1))
            cc_log(@"Info: qURL OK %@ %@", downloadURL, downloadURL.associatedValue);
        else if (!checked)
            cc_log(@"ERROR: qURL unknown response: %@ %@", downloadURL, resp);
        
        checkedURLs[downloadURL] = @(1);
        
        [NSThread sleepForTimeInterval:16.0];
    }
    
    cc_log(@"\nInfo: now rescanning %lu old resources\n", (unsigned long)queuedResourcesToRescan.count);
    i = 0;
    for (NSString *resource in queuedResourcesToRescan)
    {
        [[NSURL URLWithHost:@"www.virustotal.com" path:@"/vtapi/v2/file/rescan" query:makeString(@"apikey=%@&resource=%@", apiKey, resource)] performPOST:^(NSData *result)
        {
            let resp = result.string;
            if (resp.length)
                cc_log(@"Info: got result: %@", resp);
        }];
        [NSThread sleepForTimeInterval:20.0];
        if (++i % 100 == 0)
            cc_log(@"\nInfo: rescanned %i of %lu apps\n", i, (unsigned long)queuedResourcesToRescan.count);
    }
    [NSThread sleepForTimeInterval:10.0]; // if we quit now we don't get the last responses in the background thread anymore
    NSBeep(); // finished info for long running jobs
}


int main(int argc, const char * argv[])
{
    @autoreleasepool
    {
        cc = [CoreLib new];
        
        apiKey = NSProcessInfo.processInfo.environment[@"VIRUSTOTAL_APIKEY"];

        if (!apiKey.length)
        {
            cc_log_error(@"Please specify your VirusTotal API key in the 'VIRUSTOTAL_APIKEY' environment variable");
            exit(1);
        }
        
        if (argc != 2)
        {
            cc_log_error(@"Usage:\n\n%@ --all\nOR\n%@ <cask_name>", @(argv[0]), @(argv[0]));
            exit(1);
        }
        else
        {
            let caskDir = @"/usr/local/Homebrew/Library/Taps/homebrew/homebrew-cask/Casks";

            
            if ([@"--all" isEqualToString:@(argv[1])])
            {
                let moreCaskDirs = @[@"/usr/local/Homebrew/Library/Taps/homebrew/homebrew-cask-drivers/Casks",
                                    @"/usr/local/Homebrew/Library/Taps/homebrew/homebrew-cask-versions/Casks"];

                cc_log(@"Info: going to check all locally stored casks - hopefully you did run 'brew update' beforehand ( %@ )", caskDir);
                var caskFiles = caskDir.directoryContentsAbsolute;
                for (NSString *otherCaskDir in moreCaskDirs)
                    caskFiles = [caskFiles arrayByAddingObjectsFromArray:otherCaskDir.directoryContentsAbsolute];
                checkVirusTotal(caskFiles);
            }
            else
            {
                let caskFile = @[caskDir, makeString(@"%@.rb", @(argv[1]))].path;
                
                if (caskFile.fileExists)
                {
                    cc_log(@"Info: going to check only the cask %@ - hopefully you did run 'brew update' beforehand", caskFile);
                
                    checkVirusTotal(@[caskFile]);
                }
                else
                {
                    cc_log_error(@"The specified cask does not exist: %@", caskFile);
                    exit(1);
                }
            }
        }
    }
    return 0;
}
