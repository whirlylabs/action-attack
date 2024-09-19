package com.whirlylabs.actionattack.scan.yaml

import com.whirlylabs.actionattack.Finding

/** Base trait for YAML scanners.
  */
trait YamlScanner {

  /** The vulnerability kind this scanner handles.
    */
  val kind: String

  /** The entrypoint for the scanner.
    *
    * @return
    *   any findings, if any.
    */
  def scan(
    actionsFile: GitHubActionsWorkflow,
    commitSha: String = "<unknown>",
    filepath: String = "<unknown>"
  ): List[Finding]

}
