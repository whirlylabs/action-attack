package com.whirlylabs.actionattack.scan.yaml

/** Facilitates the transformation of a YAML to simplify the complexity of scans.
  */
trait YamlTransformer {

  /** The entrypoint for the workflow transformation.
    * @param actionsFile
    *   the input file.
    * @return
    *   the transformed YAML file.
    */
  def transform(actionsFile: GitHubActionsWorkflow): GitHubActionsWorkflow

}
