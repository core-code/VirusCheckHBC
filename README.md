# VirusCheckHBC
CLI tool to check all of 'Homebrew Cask' using VirusTotal

Installation:

```shell
# Clone `CoreLib` and this directory next (!) to each other:
cd "$(mktemp -d)" || exit 1 # Temporary directory

git clone https://github.com/core-code/CoreLib.git
git clone https://github.com/core-code/VirusCheckHBC.git

# Compile and install (will be in /usr/local/bin):
cd VirusCheckHBC || exit 1
xcodebuild install DSTROOT=/
```

Run it by speciying your APIKEY:

```shell
VIRUSTOTAL_APIKEY=bla VirusCheckHBC
```
