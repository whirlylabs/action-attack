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
      case Some((TaintedActionsOutputSource(_, summary, workflowAction), affectedString)) =>
        Option(VulnerableActionInjection(jobName, affectedString, workflowAction, summary))
      case Some((_, affectedString))              => Option(DirectInjection(jobName, affectedString))
      case None if hasAliasedInjection(sink, env) => Option(AliasedInjection(jobName, sink))
      case _                                      => None
    }
  }

  private def hasDirectInjection(
    sink: InterpolatedString
  )(implicit sources: Set[AttackerControlledSource]): Option[(AttackerControlledSource, LocatedString)] = {
    sources.flatMap {
      case s @ ExactLiteralSource(source) => sink.interpolations.find(_.value == source).map(x => s -> x)
      case s @ RegexLiteralSource(source) =>
        sink.interpolations.find(x => x.value.matches(source)).map(x => s -> x)
      case s @ TaintedActionsOutputSource(source, _, _) =>
        sink.interpolations.find(_.value == source).map(x => s -> x)
    }.headOption
  }

  private def hasAliasedInjection(sink: InterpolatedString, env: Map[String, YamlString])(implicit
    sources: Set[AttackerControlledSource]
  ): Boolean = {
    sink.interpolations
      .flatMap {
        case x if x.value.startsWith("env.") => Option(x.value.stripPrefix("env."))
        case _                               => None
      }
      .exists { key =>
        env.contains(key) && sources.exists {
          case RegexLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => value.matches(source)
              case InterpolatedString(_, _, interpolations) => interpolations.exists(x => x.value.matches(source))
            }
          case other =>
            env(key) match {
              case LocatedString(value, _)                  => other.value == value
              case InterpolatedString(_, _, interpolations) => interpolations.map(_.value).contains(other.value)
            }
        }
      }
  }

}
