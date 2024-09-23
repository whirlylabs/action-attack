# Action Attack
A GitHub Actions vulnerability miner and scanner.

## Pre-requisites

* `git` and `sbt` are installed.
* That [Octoscan](https://github.com/synacktiv/octoscan) is installed and accessible on the `$PATH` variable via 
`octoscan`.
* A GitHub token. The easiest is to create a fine-grained token with no access given to any repositories 
(which is the default). `.env` has been added to `.gitignore` as a place to store this during development.

## Installation

```
sbt stage
```

## Usage

Below is the usage information when running `./action-attack`
```
Usage: action-attack [monitor|review|report] [options]

  --help                   Usage information
  -o, --output <value>     The storage path for the database (default is in-memory)
Command: monitor [options]
Monitors open-source GitHub projects for potentially vulnerable applications
  --token <value>          A fine-grained personal access GitHub token
Command: review
Presents findings of potentially vulnerable applications for manual review
Command: report
Generates a report of all verified findings
```
