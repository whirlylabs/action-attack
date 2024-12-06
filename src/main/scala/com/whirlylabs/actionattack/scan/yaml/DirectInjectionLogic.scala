package com.whirlylabs.actionattack.scan.yaml

trait DirectInjectionLogic { this: ExpressionInjectionScanner =>

  import ExpressionInjectionScanner.*

  protected def scanForDirectInjection(job: Job, jobName: String): List[ExpressionInjectionFinding] = {
    job.steps
      .flatMap(step => step.sinks.map(sink => sink -> step.env))
      .flatMap {
        case (sink: InterpolatedString, env: Map[String, YamlString]) => checkInterpolatedString(jobName, env, sink)
        case _                                                        => None
      }
  }

  protected def checkInterpolatedString(
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

  private def hasDirectInjection(sink: InterpolatedString): Boolean = {
    ExpressionInjectionScanner.sources.exists {
      case ExactLiteralSource(source) => sink.interpolations.contains(source)
      case RegexLiteralSource(source) => sink.interpolations.exists(_.matches(source))
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
          case ExactLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => source == value
              case InterpolatedString(_, _, interpolations) => interpolations.contains(source)
            }
          case RegexLiteralSource(source) =>
            env(key) match {
              case LocatedString(value, _)                  => value.matches(source)
              case InterpolatedString(_, _, interpolations) => interpolations.exists(_.matches(source))
            }
        }
      }
  }

}
