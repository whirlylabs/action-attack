package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory

import java.nio.file.Path
import java.nio.file.Files
import scala.util.Using

class ActionAttack(config: Config) {

  private val logger = LoggerFactory.getLogger(getClass)

  def run(): Unit = Using.resource(Database(config.dbPath)) { db =>
    config.mode match {
      case OperatingMode.Monitor =>
        config.ghToken.orElse {
          val envFile = Path.of(".env")
          if (Files.exists(envFile)) {
            Option(Files.readString(envFile).trim)
          } else {
            None
          }
        } match {
          case Some(token) if !token.startsWith("github_pat_") =>
            logger.error("Invalid GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
          case Some(token) => Monitor(db, token).start()
          case None =>
            logger.error("No GitHub token given or found under `.env`, exiting...")
            sys.exit(1)
        }
      case OperatingMode.Review => logger.warn("Unimplemented")
      case OperatingMode.Report =>
        if (config.dbPath.isEmpty) {
          logger.error("Database path not set, no results to generate a report from")
          sys.exit(1)
        } else {
          Report(db).generateFindings()
        }
    }
  }

}

case class Config(
  mode: OperatingMode = OperatingMode.Monitor,
  dbPath: Option[Path] = None,
  ghToken: Option[String] = None
)

sealed trait OperatingMode

object OperatingMode {
  case object Monitor extends OperatingMode

  case object Review extends OperatingMode

  case object Report extends OperatingMode
}
