package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.scan.WorkflowAction
import com.whirlylabs.actionattack.{ActionSummary, Finding}

class ExpressionInjectionScanner extends YamlScanner {

  override val kind: String = "expression-injection"

  override def scan(
    actionsFile: GitHubActionsWorkflow,
    commitSha: String,
    filepath: String,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[Finding] = {
    actionsFile.jobs
      .flatMap { case (jobName, job) => findExpressionInjections(jobName, job, actionSummaries) }
      .map { (finding: ExpressionInjectionFinding) =>
        val kind       = finding.getClass.getSimpleName
        val actionNode = finding.node
        val rawSnippet = finding match {
          case x: VulnerableActionInjection => s"${x.relevantSummary.inputKey}: ${actionNode.code.strip()}"
          case _                            => actionNode.code.strip()
        }
        val shortenedCode = finding match {
          case VulnerableActionInjection(_, _, _, summary) =>
            if (summary.snippet.sizeIs > 40) s"${summary.snippet.take(37)}[...]" else summary.snippet
          case _ => if (rawSnippet.sizeIs > 40) s"${rawSnippet.take(37)}[...]" else rawSnippet
        }
        val message = finding match {
          case DirectInjection(jobName, _)  => s"'$jobName' has a direct command injection at '$shortenedCode'"
          case AliasedInjection(jobName, _) => s"'$jobName' has an aliased command injection at '$shortenedCode'"
          case VulnerableActionInjection(
                jobName,
                _,
                action,
                ActionSummary(_, _, _, inputKey, sinkName, _, _, false, _)
              ) =>
            s"'$jobName' may define an argument for `$sinkName` (`$shortenedCode`) in $action at input '$inputKey'"
          case VulnerableActionInjection(
                jobName,
                _,
                action,
                ActionSummary(_, _, _, inputKey, sinkName, _, _, true, _)
              ) =>
            s"'$jobName' may define an output for `$sinkName` (`$shortenedCode`) in $action at input '$inputKey'"
        }
        Finding(
          kind = kind,
          commitSha = commitSha,
          message = message,
          snippet = Option(rawSnippet),
          filepath = filepath,
          line = actionNode.location.line,
          column = actionNode.location.column,
          columnEnd = actionNode.location.columnEnd
        )
      }
      .toList
  }

  sealed trait ExpressionInjectionFinding {
    def jobName: String
    def node: ActionNode
  }

  private case class DirectInjection(jobName: String, node: ActionNode) extends ExpressionInjectionFinding

  private case class AliasedInjection(jobName: String, node: ActionNode) extends ExpressionInjectionFinding

  private case class VulnerableActionInjection(
    jobName: String,
    node: ActionNode,
    relevantAction: WorkflowAction,
    relevantSummary: ActionSummary
  ) extends ExpressionInjectionFinding

  private def checkInterpolatedString(
    jobName: String,
    env: Map[String, YamlString],
    sink: InterpolatedString
  ): Option[ExpressionInjectionFinding] = {
    // TODO: May want to make this more precise feedback
    if (hasDirectInjection(sink)) {
      Option(DirectInjection(jobName, sink))
    } else if (hasAliasedInjection(sink, env)) {
      Option(AliasedInjection(jobName, sink))
    } else {
      None
    }
  }

  private def findExpressionInjections(
    jobName: String,
    job: Job,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[ExpressionInjectionFinding] = {
    val directInjections = job.steps
      .flatMap(step => step.sinks.map(sink => sink -> step.env))
      .flatMap {
        case (sink: InterpolatedString, env: Map[String, YamlString]) => checkInterpolatedString(jobName, env, sink)
        case _                                                        => None
      }
    // Check action summaries
    val vulnerableActions = job.steps
      .flatMap { step =>
        step.uses.iterator.flatMap { externalAction =>
          externalAction.value match {
            case s"$owner/$name@$version" =>
              val workflowAction = WorkflowAction(owner, name, version)
              actionSummaries.get(workflowAction) match {
                case Some(summaries) =>
                  summaries.flatMap {
                    case summary @ ActionSummary(_, _, _, inputKey, _, _, _, _, _)
                        if step.`with`.keySet
                          .contains(inputKey) && step.`with`(inputKey).isInstanceOf[InterpolatedString] =>
                      val inputParam = step.`with`(inputKey).asInstanceOf[InterpolatedString]
                      checkInterpolatedString(jobName, step.env, inputParam).map(_ =>
                        VulnerableActionInjection(jobName, inputParam, workflowAction, summary)
                      )
                    case _ =>
                      None
                  }
                case None => Nil
              }
            case _ => None
          }
        }
      }
    directInjections ++ vulnerableActions
  }

  private def hasDirectInjection(sink: InterpolatedString): Boolean = {
    ExpressionInjectionScanner.sources.exists {
      case ExpressionInjectionScanner.ExactLiteralSource(source) => sink.interpolations.contains(source)
      case ExpressionInjectionScanner.RegexLiteralSource(source) => sink.interpolations.exists(_.matches(source))
    }
  }

  private def hasAliasedInjection(sink: InterpolatedString, env: Map[String, YamlString]): Boolean = {
    sink.interpolations
      .flatMap {
        case x if x.startsWith("env.") => Option(x.stripPrefix("env."))
        case _                         => None
      }
      .exists { key =>
        env.contains(key) && ExpressionInjectionScanner.sources.exists {
          case ExpressionInjectionScanner.ExactLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => source == value
              case InterpolatedString(_, _, interpolations) => interpolations.contains(source)
            }
          case ExpressionInjectionScanner.RegexLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => value.matches(source)
              case InterpolatedString(_, _, interpolations) => interpolations.exists(_.matches(source))
            }
        }
      }
  }

}

object ExpressionInjectionScanner {

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
//    RegexLiteralSource("steps\\..*\\.outputs\\..*"), // fixme: These are low-confidence rules
//    RegexLiteralSource("needs\\..*\\.outputs\\..*")
  )

  sealed trait AttackerControlledSource {
    def value: String
  }

  case class ExactLiteralSource(value: String) extends AttackerControlledSource

  case class RegexLiteralSource(value: String) extends AttackerControlledSource
}
