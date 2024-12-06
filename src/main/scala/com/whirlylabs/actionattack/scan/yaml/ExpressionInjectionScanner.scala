package com.whirlylabs.actionattack.scan.yaml
import com.whirlylabs.actionattack.scan.WorkflowAction
import com.whirlylabs.actionattack.{ActionSummary, Finding}

class ExpressionInjectionScanner extends YamlScanner with DirectInjectionLogic with DangerousSinkInExternalActionLogic {

  import ExpressionInjectionScanner.*
  override val kind: String = "expression-injection"

  override def scan(
    actionsFile: GitHubActionsWorkflow,
    commitSha: String,
    filepath: String,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[Finding] = {
    actionsFile.jobs
      .flatMap { case (jobName, job) => findExpressionInjections(jobName, job, actionSummaries) }
      .map(transformFinding(_, commitSha, filepath))
      .toList
  }

  private def transformFinding(finding: ExpressionInjectionFinding, commitSha: String, filepath: String) = {
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
      case VulnerableActionInjection(jobName, _, action, ActionSummary(_, _, _, inputKey, sinkName, _, _, false, _)) =>
        s"'$jobName' may define an argument for `$sinkName` (`$shortenedCode`) in $action at input '$inputKey'"
      case VulnerableActionInjection(jobName, _, action, ActionSummary(_, _, _, inputKey, sinkName, _, _, true, _)) =>
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

  private def findExpressionInjections(
    jobName: String,
    job: Job,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[ExpressionInjectionFinding] = {
    val directInjections  = scanForDirectInjection(job, jobName)
    val vulnerableActions = scanForVulnerableSummaryInputUsage(job, jobName, actionSummaries)
    directInjections ++ vulnerableActions
  }

}

object ExpressionInjectionScanner {

  sealed trait AttackerControlledSource {
    def value: String
  }

  case class ExactLiteralSource(value: String) extends AttackerControlledSource

  case class RegexLiteralSource(value: String) extends AttackerControlledSource

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

  sealed trait ExpressionInjectionFinding {
    def jobName: String

    def node: ActionNode
  }

  case class DirectInjection(jobName: String, node: ActionNode) extends ExpressionInjectionFinding

  case class AliasedInjection(jobName: String, node: ActionNode) extends ExpressionInjectionFinding

  case class VulnerableActionInjection(
    jobName: String,
    node: ActionNode,
    relevantAction: WorkflowAction,
    relevantSummary: ActionSummary
  ) extends ExpressionInjectionFinding
}
