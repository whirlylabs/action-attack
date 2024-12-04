package com.whirlylabs.actionattack.scan.yaml

import com.whirlylabs.actionattack.scan.WorkflowAction
import com.whirlylabs.actionattack.{Action, ActionSummary, Finding}

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
    commitSha: String,
    filepath: String,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[Finding]

}
