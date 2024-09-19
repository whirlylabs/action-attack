package com.whirlylabs.actionattack.scan.yaml

import com.whirlylabs.actionattack.Finding

/** Base trait for YAML scanners.
  */
trait YamlScanner {

  /** The entrypoint for the scanner.
    *
    * @return
    *   any findings, if any.
    */
  def scan(actionsFile: GitHubActionsWorkflow): List[Finding]

}
