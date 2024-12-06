# Action Attack
A GitHub Actions vulnerability miner and scanner.

## Pre-requisites

* `git` and `sbt` are installed.
* A GitHub token. The easiest is to create a fine-grained token with no access given to any repositories 
(which is the default). `.env` has been added to `.gitignore` as a place to store this during development.

## Installation

```
sbt stage
```

## Usage

Below is the usage information when running `./action-attack`
```
Usage: action-attack [monitor|scan|review|report] [options]

  --help                   Usage information
  -o, --output <value>     The storage path for the database (default is in-memory)
Command: monitor [options]
Monitors open-source GitHub projects for potentially vulnerable applications
  --token <value>          A fine-grained personal access GitHub token (will alternatively look for token under `.env`)
Command: scan [options]
Scans the provided GitHub repository for potentially vulnerable workflows
  --owner <value>          The owner of the repository
  --repo <value>           The name of the repository
  --commitHash <value>     The commit hash to scan
Command: review
Presents findings of potentially vulnerable applications for manual review
Command: report
Generates a report of all verified findings
```

## Review Mode

This mode allows one to review the findings in the database and verify them. Only verified findings will appear in the
report resulting from the `report` command.

The controls for review mode are:
```
Left/Right Arrows: Navigate between repository
Up/Down Arrows: Navigate between entries
Y/N: Validate a finding as valid or invalid
Q: Quit
```
Note: Line numbers are extracted mostly from the YAML DOM, so these are a best approximations when an exploit is within
a body of text.

## Example: AutoGPT

One example of a notable expression injection is on AutoGPT. An example of scanning this once-off is as follows:
```
./action-attack scan --owner="Significant-Gravitas" \
    --repo="AutoGPT" \
    --commitHash="ce33e238a964ebe1827a29c4bea1cba271c39a34" \
    -o "db.sqlite3"
```
One can then review the finding with 
```
./action-attack review -o "db.sqlite3"
```
And, finally, to generate a simple report of validated findings:
```
./action-attack report -o "db.sqlite3"
```

### Another example

```
./action-attack scan --owner="All-Hands-AI" \
    --repo="OpenHands" \
    --commitHash="01ae22ef57d497f7cfdfba96a99b96af06be5a05" \
    -o "db.sqlite3"
```