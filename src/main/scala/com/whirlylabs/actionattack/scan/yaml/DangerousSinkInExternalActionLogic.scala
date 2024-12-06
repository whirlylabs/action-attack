package com.whirlylabs.actionattack.scan.yaml

import com.whirlylabs.actionattack.ActionSummary
import com.whirlylabs.actionattack.scan.WorkflowAction

trait DangerousSinkInExternalActionLogic { this: ExpressionInjectionScanner =>

  import ExpressionInjectionScanner.*

  protected def scanForVulnerableSummaryInputUsage(
    job: Job,
    jobName: String,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[VulnerableActionInjection] = {
    job.steps
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
  }

}
