package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.Finding

class CommandInjectionScanner extends YamlScanner {

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
    val attackerControlledSources = CommandInjectionScanner.sources
    job.steps
      .flatMap { step =>
        step.run.map(run => run -> step.env)
      }
      .flatMap {
        case (run: InterpolatedString, env: Map[String, YamlString]) =>
          val hasDirectInjection  = attackerControlledSources.exists(run.interpolations.contains)
          val hasAliasedInjection = findAliasedInjection(run, env)
          // TODO: May want to make this precise feedback
          if (hasDirectInjection || hasAliasedInjection) {
            Option(run)
          } else {
            None
          }
        case _ => None
      }
  }

  private def findAliasedInjection(run: InterpolatedString, env: Map[String, YamlString]): Boolean = {
    run.interpolations.exists { x =>
      val key = x.stripPrefix("env.")
      env.contains(key) && CommandInjectionScanner.sources.exists { source =>
        env(key) match {
          case LocatedString(value, _)                  => source == value
          case InterpolatedString(_, _, interpolations) => interpolations.contains(source)
        }
      }
    }
  }

}

object CommandInjectionScanner {
  // TODO: Incorporate full list and regex
  val sources: Set[String] = Set("github.event_name", "github.event.issue.body")
}
