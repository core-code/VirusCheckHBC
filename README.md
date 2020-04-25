# VirusCheckHBC
CLI tool to check all of 'Homebrew Cask' using VirusTotal

Usage:

Make sure you checkout the 'CoreLib' next (!) to the VirusCheckHBC folder:

`git clone git@github.com:core-code/CoreLib.git`
`git clone git@github.com:core-code/VirusCheckHBC.git`


Now compile and install it: 

`cd VirusCheckHBC/`
`xcodebuild install DSTROOT=/`

run it by speciying your APIKEY:

`VIRUSTOTAL_APIKEY=bla VirusCheckHBC`
