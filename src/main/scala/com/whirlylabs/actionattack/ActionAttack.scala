package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.ui.TUIRunner
import org.slf4j.LoggerFactory

import java.nio.file.Path
import java.nio.file.Files
import scala.util.Using

class ActionAttack(config: Config) {

  private val logger = LoggerFactory.getLogger(getClass)

  def run(): Unit = Using.resource(Database(config.dbPath)) { db =>
    config.mode match {
      case OperatingMode.Monitor =>
        checkToken(config) match {
          case Some(token) if !token.startsWith("github_pat_") =>
            logger.error("Invalid GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
          case Some(token) => Monitor(db, token).start()
          case None =>
            logger.error("No GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
        }
      case OperatingMode.Review =>
        checkToken(config) match {
          case Some(token) if !token.startsWith("github_pat_") =>
            logger.error("Invalid GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
          case Some(token) =>
            val unvalidatedFindings = db.getUnvalidatedFindingsForReview
            if unvalidatedFindings.isEmpty then logger.info("No findings for review")
            else TUIRunner().run(db, unvalidatedFindings, token)
          case None =>
            logger.error("No GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
        }
      case OperatingMode.Report =>
        if (config.dbPath.isEmpty) {
          logger.error("Database path not set, no results to generate a report from")
          sys.exit(1)
        } else {
          Report(db).generateFindings()
        }
      case OperatingMode.Scan =>
        checkToken(config) match {
          case Some(token) if !token.startsWith("github_pat_") =>
            logger.error("Invalid GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
          case Some(token) =>
            if (config.owner.isEmpty || config.repo.isEmpty || config.commitSha.isEmpty) {
              logger.error("GitHub information missing, exiting...")
              sys.exit(1)
            } else {
              Scanner(db).run(Repository(-1, config.owner.get, config.repo.get), config.commitSha)
            }
          case None =>
            logger.error("No GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
        }
    }
  }

  private def checkToken(config: Config) = {
    config.ghToken.orElse {
      val envFile = Path.of(".env")
      if (Files.exists(envFile)) {
        Option(Files.readString(envFile).trim)
      } else {
        None
      }
    }
  }

}

case class Config(
  mode: OperatingMode = OperatingMode.Monitor,
  dbPath: Option[Path] = None,
  ghToken: Option[String] = None,
  owner: Option[String] = None,
  repo: Option[String] = None,
  commitSha: Option[String] = None
)

sealed trait OperatingMode

object OperatingMode {
  case object Monitor extends OperatingMode

  case object Review extends OperatingMode

  case object Report extends OperatingMode

  case object Scan extends OperatingMode
}
