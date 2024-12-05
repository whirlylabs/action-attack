package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.js.JavaScriptScanner
import com.whirlylabs.actionattack.PathExt
import com.whirlylabs.actionattack.{Action, Database, Repository, Scanner}
import com.whirlylabs.actionattack.scan.yaml.GitHubActionsWorkflow
import org.slf4j.LoggerFactory

import scala.util.{Failure, Success}

object ExternalActionsScanner {

  private val logger = LoggerFactory.getLogger(getClass)

  /** Gets the names for all the actions used on this repository
    *
    * @return
    *   List of actions names in the form of `actionOwner/actionName@version`
    */
  def fetchActionsNames(workflowFiles: List[GitHubActionsWorkflow]): List[WorkflowAction] = {
    logger.debug(s"Running check for plugins on repo")
    // Download plugins on files
    workflowFiles.flatMap { actionsFile =>
      actionsFile.jobs.values.flatMap { job =>
        job.steps.flatMap { step =>
          step.uses.map(_.value.strip).getOrElse("") match {
            case s"$owner/$name@$version" => Option(WorkflowAction(owner, name, version))
            case _                        => None
          }
        }
      }
    }.distinct
  }

  def scanExternalAction(db: Database, action: Action): Unit = {
    db.getRepository(action.repositoryId) match {
      case Some(repo @ Repository(_, owner, name)) =>
        logger.info(s"Scanning external action $owner/$name@${action.version}")

        Scanner.cloneRepo(repo, action.version, fetchTags = true) match {
          case Success(targetDir) =>
            try {
              val results = JavaScriptScanner(targetDir).runScan
              db.summarizeAction(action.id, results)
            } finally {
              targetDir.delete()
            }
          case Failure(e) =>
            logger.warn(s"Error external action $owner/$name@${action.version}", e)
            db.summarizeAction(action.id, Nil)
        }

      case None =>
        logger.error(s"No repository associated with this action $action, will mark it scanned")
        db.summarizeAction(action.id, Nil)
    }
  }

}

case class WorkflowAction(owner: String, name: String, version: String) {
  override def toString: String = s"$owner/$name@$version"
}
