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
          // TODO: May want to make this precise feedback
          if (hasDirectInjection(run) || hasAliasedInjection(run, env)) {
            Option(run)
          } else {
            None
          }
        case _ => None
      }
  }

  private def hasDirectInjection(run: InterpolatedString): Boolean = {
    CommandInjectionScanner.sources.exists {
      case CommandInjectionScanner.ExactLiteralSource(source) => run.interpolations.contains(source)
      case CommandInjectionScanner.RegexLiteralSource(source) => run.interpolations.exists(_.matches(source))
    }
  }

  private def hasAliasedInjection(run: InterpolatedString, env: Map[String, YamlString]): Boolean = {
    run.interpolations
      .flatMap {
        case x if x.startsWith("env.") => Option(x.stripPrefix("env."))
        case _                         => None
      }
      .exists { key =>
        env.contains(key) && CommandInjectionScanner.sources.exists {
          case CommandInjectionScanner.ExactLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => source == value
              case InterpolatedString(_, _, interpolations) => interpolations.contains(source)
            }
          case CommandInjectionScanner.RegexLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => value.matches(source)
              case InterpolatedString(_, _, interpolations) => interpolations.exists(_.matches(source))
            }
        }
      }
  }

}

object CommandInjectionScanner {

  val sources: Set[AttackerControlledSource] = Set(
    ExactLiteralSource("github.event.issue.title"),
    ExactLiteralSource("github.event.issue.body"),
    ExactLiteralSource("github.event.pull_request.title"),
    ExactLiteralSource("github.event.pull_request.body"),
    ExactLiteralSource("github.event.comment.body"),
    ExactLiteralSource("github.event.review.body"),
    RegexLiteralSource("github\\.event\\.pages\\..*\\.page\\_name"),
    RegexLiteralSource("github\\.event\\.commits\\..*\\.message"),
    ExactLiteralSource("github.event.head_commit.message"),
    ExactLiteralSource("github.event.head_commit.author.email"),
    ExactLiteralSource("github.event.head_commit.author.name"),
    RegexLiteralSource("github\\.event\\.commits\\..*\\.author\\.email"),
    RegexLiteralSource("github\\.event\\.commits\\..*\\.author\\.name"),
    ExactLiteralSource("github.event.pull_request.head.ref"),
    ExactLiteralSource("github.event.pull_request.head.label"),
    ExactLiteralSource("github.event.pull_request.head.repo.default_branch"),
    ExactLiteralSource("github.head_ref")
  )

  sealed trait AttackerControlledSource {
    def value: String
  }

  case class ExactLiteralSource(value: String) extends AttackerControlledSource

  case class RegexLiteralSource(value: String) extends AttackerControlledSource
}
