package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.Finding

class CommandInjection extends YamlScanner {

  override val kind: String = "command-injection"

  override def scan(
    actionsFile: GitHubActionsWorkflow,
    commitSha: String = "<unknown>",
    filepath: String = "<unknown>"
  ): List[Finding] = {
    actionsFile.jobs
      .flatMap { case (jobName, job) => findCommandInjections(job).map(a => jobName -> a) }
      .map { case (jobName, actionNode) =>
        Finding(
          kind = kind,
          commitSha = commitSha,
          message = s"'$jobName' has command injection at '${actionNode.code.strip()}'",
          snippet = Option(actionNode.code.strip()),
          filepath = filepath,
          line = actionNode.location.line,
          column = actionNode.location.column,
          columnEnd = actionNode.location.columnEnd
        )
      }
      .toList
  }

  private def findCommandInjections(job: Job): List[ActionNode] = {
    job.steps.flatMap(_.run).filter { run =>
      run.value.contains("${{ github.event_name }}")
    }
  }

}
