package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory

import java.nio.file.Path
import scala.util.Using

class ActionAttack(config: Config) {

  private val logger = LoggerFactory.getLogger(getClass)

  def run(): Unit = Using.resource(Database()) { db =>
    logger.info("Hello, world!")
    config.mode match {
      case OperatingMode.Monitor => config.ghToken.foreach(Monitor(db, _).start())
      case OperatingMode.Review  => logger.warn("Unimplemented")
      case OperatingMode.Report  => logger.warn("Unimplemented")
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
