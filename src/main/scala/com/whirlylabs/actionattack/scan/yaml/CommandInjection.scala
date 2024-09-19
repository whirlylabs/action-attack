package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.Finding

class CommandInjection extends YamlScanner {

  override def scan(actionsFile: GitHubActionsWorkflow): List[Finding] = Nil

}
