package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.Finding

class CommandInjectionScanner extends YamlScanner {

  override val kind: String = "command-injection"

  override def scan(actionsFile: GitHubActionsWorkflow, commitSha: String, filepath: String): List[Finding] = {
    actionsFile.jobs
      .flatMap { case (jobName, job) => findCommandInjections(jobName, job) }
      .map { case CommandInjectionFinding(jobName, actionNode, kind) =>
        val rawSnippet    = actionNode.code.strip()
        val shortenedCode = if (rawSnippet.sizeIs > 40) s"${rawSnippet.take(37)}[...]" else rawSnippet
        Finding(
          kind = kind,
          commitSha = commitSha,
          message = s"'$jobName' has command injection at '$shortenedCode'",
          snippet = Option(rawSnippet),
          filepath = filepath,
          line = actionNode.location.line,
          column = actionNode.location.column,
          columnEnd = actionNode.location.columnEnd
        )
      }
      .toList
  }

  private case class CommandInjectionFinding(jobName: String, node: ActionNode, kind: String)

  private def findCommandInjections(jobName: String, job: Job): List[CommandInjectionFinding] = {
    job.steps
      .flatMap(step => step.sinks.map(sink => sink -> step.env))
      .flatMap {
        case (sink: InterpolatedString, env: Map[String, YamlString]) =>
          // TODO: May want to make this more precise feedback
          if (hasDirectInjection(sink)) {
            Option(CommandInjectionFinding(jobName, sink, s"$kind-direct"))
          } else if (hasAliasedInjection(sink, env)) {
            Option(CommandInjectionFinding(jobName, sink, s"$kind-aliased"))
          } else {
            None
          }
        case _ => None
      }
  }

  private def hasDirectInjection(sink: InterpolatedString): Boolean = {
    CommandInjectionScanner.sources.exists {
      case CommandInjectionScanner.ExactLiteralSource(source) => sink.interpolations.contains(source)
      case CommandInjectionScanner.RegexLiteralSource(source) => sink.interpolations.exists(_.matches(source))
    }
  }

  private def hasAliasedInjection(sink: InterpolatedString, env: Map[String, YamlString]): Boolean = {
    sink.interpolations
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
    ExactLiteralSource("github.head_ref"),
    RegexLiteralSource("steps\\..*\\.outputs\\..*"),
    RegexLiteralSource("needs\\..*\\.outputs\\..*")
  )

  sealed trait AttackerControlledSource {
    def value: String
  }

  case class ExactLiteralSource(value: String) extends AttackerControlledSource

  case class RegexLiteralSource(value: String) extends AttackerControlledSource
}
