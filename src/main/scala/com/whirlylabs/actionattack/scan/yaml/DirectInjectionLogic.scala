package com.whirlylabs.actionattack.scan.yaml

trait DirectInjectionLogic { this: ExpressionInjectionScanner =>

  import ExpressionInjectionScanner.*

  protected def scanForDirectInjection(job: Job, jobName: String)(implicit
    sources: Set[AttackerControlledSource]
  ): List[ExpressionInjectionFinding] = {
    job.steps
      .flatMap(step => step.sinks.map(sink => sink -> step.env))
      .flatMap {
        case (sink: InterpolatedString, env: Map[String, YamlString]) => checkInterpolatedString(jobName, env, sink)
        case _                                                        => None
      }
  }

  protected def checkInterpolatedString(jobName: String, env: Map[String, YamlString], sink: InterpolatedString)(
    implicit sources: Set[AttackerControlledSource] = ExpressionInjectionScanner.sources
  ): Option[ExpressionInjectionFinding] = {
    hasDirectInjection(sink) match {
      case Some(TaintedActionsOutputSource(_, summary, workflowAction)) =>
        Option(VulnerableActionInjection(jobName, sink, workflowAction, summary))
      case Some(_)                                => Option(DirectInjection(jobName, sink))
      case None if hasAliasedInjection(sink, env) => Option(AliasedInjection(jobName, sink))
      case _                                      => None
    }
  }

  private def hasDirectInjection(
    sink: InterpolatedString
  )(implicit sources: Set[AttackerControlledSource]): Option[AttackerControlledSource] = {
    sources.find {
      case ExactLiteralSource(source)               => sink.interpolations.contains(source)
      case RegexLiteralSource(source)               => sink.interpolations.exists(_.matches(source))
      case TaintedActionsOutputSource(source, _, _) => sink.interpolations.contains(source)
    }
  }

  private def hasAliasedInjection(sink: InterpolatedString, env: Map[String, YamlString])(implicit
    sources: Set[AttackerControlledSource]
  ): Boolean = {
    sink.interpolations
      .flatMap {
        case x if x.startsWith("env.") => Option(x.stripPrefix("env."))
        case _                         => None
      }
      .exists { key =>
        env.contains(key) && sources.exists {
          case RegexLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => value.matches(source)
              case InterpolatedString(_, _, interpolations) => interpolations.exists(_.matches(source))
            }
          case other =>
            env(key) match {
              case LocatedString(value, _)                  => other.value == value
              case InterpolatedString(_, _, interpolations) => interpolations.contains(other.value)
            }
        }
      }
  }

}
