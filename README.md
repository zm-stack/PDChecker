# PDChecker

## Artifact Description

### Contrent

PDChecker is an automated security analysis framework for three privacy leakage vulnerabilities in Hyperledger Fabric chaincode applying PDC. This tool is an extension of [revive](https://github.com/mgechev/revive), and is one of the main outcomes of the paper "Understanding and Detecting Privacy Leakage Vulnerabilities in Hyperledger Fabric Chaincodes".

### Structure

A description of the key folders is provided here.

- rule: All linting rules supported by this tool, each rule corresponds to a defect.
- formatter: All output formats supported by this tool.
- config: Parses all configuration information.
- lint: Contains the main functional modules of this tool, calling the linting rules for code review and the formatter to format the output.
- test: Test code for each module of this tool.
- testdata: Test cases for each linting rule.

For the description of all linting rules and other details, please refer to [revive](https://github.com/mgechev/revive).

### Files

A description of the key files in the root directory is provided here.

- main.go: Entry points to this tool
- toml files: Configuration file to be supplied at runtime, containing the linting rules and related parameters to be used.
  - defaults.toml: default config for revive.
  - chaincode.toml: config for go chaincodes.
  - chaincodePrivacy.toml: config for privacy leakage vulnerability detection in go chaincodes.
  
## Environment Setup

Any linux system capable of installing the Go runtime environment.

## Getting Started

### Installation

1. [Go installstion](https://go.dev/doc/install) (Recommend Go 1.21.1 or later version)
2. build from the source code

```bash
git clone git@github.com:pdchecker/PDChecker.git
cd PDChecker
make install
make build
```

### Usage

```bash
# Get the instruction of the command line flags
revive -h
# Sample Invocation
revive -config revive.toml -exclude file1.go -exclude file2.go -formatter friendly github.com/mgechev/revive package/...
```

- The command above will use the configuration from revive.toml
- The linter will ignore file1.go and file2.go
- The output will be formatted with the friendly formatter
- The linter will analyze github.com/mgechev/revive and the files in package

### Command Line Flags

PDChecker accepts the following command line parameters:

- `-config [PATH]` - path to config file in TOML format.
- `-exclude [PATTERN]` - pattern for files/directories/packages to be excluded for linting. You can specify the files you want to exclude for linting either as package name, list them as individual files, directories, or any combination of the three.
- `-formatter [NAME]` - formatter to be used for the output. The currently available formatters are:

  - `default` - will output the failures the same way that `golint` does.
  - `json` - outputs the failures in JSON format.
  - `ndjson` - outputs the failures as stream in newline delimited JSON (NDJSON) format.
  - `friendly` - outputs the failures when found. Shows summary of all the failures.
  - `stylish` - formats the failures in a table. Keep in mind that it doesn't stream the output so it might be perceived as slower compared to others.
  - `checkstyle` - outputs the failures in XML format compatible with that of Java's [Checkstyle](https://checkstyle.org/).
- `-max_open_files` -  maximum number of open files at the same time. Defaults to unlimited.
- `-set_exit_status` - set exit status to 1 if any issues are found, overwrites `errorCode` and `warningCode` in config.
- `-version` - get revive version.

### Validate Functionality

```bash
# Make sure you are in the root directory of your project
revive -config chaincode.toml testdata/chaincode/privacy.go 
```

If everything is OK, you will get the following output.

```bash
testdata/chaincode/privacy.go:77:29: & detected. The address is random, which may lead to consensus errors.
testdata/chaincode/privacy.go:107:38: & detected. The address is random, which may lead to consensus errors.
testdata/chaincode/privacy.go:64:20: * detected. Pointer is not recommended in chaincode if not necessary.
testdata/chaincode/privacy.go:98:37: * detected in return value. Pointer is not recommended in chaincode if not necessary.
testdata/chaincode/privacy.go:99:19: * detected. Pointer is not recommended in chaincode if not necessary.
testdata/chaincode/privacy.go:84:10: Privacy leakage in arguments. The private data should be passed via GetTransient.
testdata/chaincode/privacy.go:93:3: Privacy leakage in return. The query of private data should be read-only
testdata/chaincode/privacy.go:95:2: Privacy leakage in return. The query of private data should be read-only
testdata/chaincode/privacy.go:10:2: External library found: "github.com/pkg/errors". Please ensure this package does not return inconsistent results.
testdata/chaincode/privacy.go:30:27: parameter 'stub' seems to be unchecked.
testdata/chaincode/privacy.go:36:29: parameter 'stub' seems to be unchecked.
testdata/chaincode/privacy.go:51:35: parameter 'stub' seems to be unchecked.
testdata/chaincode/privacy.go:38:2: Unhandled error in call to function fmt.Println
testdata/chaincode/privacy.go:45:3: Unhandled error in call to function fmt.Println
```

## Reproducibility Instructions:

Please refer to the following [link](https://github.com/zm-stack/Chaincode). This repository contains all the data needed for the experiment, as well as the steps to reproduce the experiment results.
