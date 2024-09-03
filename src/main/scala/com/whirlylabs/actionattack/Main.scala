package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory
import scopt.OptionParser

import java.nio.file.{Files, Path, Paths}
import scala.util.Try

object Main {

  private val logger = LoggerFactory.getLogger(getClass)

  def main(args: Array[String]): Unit = {
    optionParser.parse(args, Config()) match {
      case Some(config) =>
        logger.info(s"Running in ${config.mode} mode...")
        ActionAttack(config).run()
      case None =>
        logger.error("Unable to parse command line arguments!")
    }
  }

  private val optionParser: OptionParser[Config] = new OptionParser[Config]("action-attack") {

    help("help")
      .text("Usage information")

    opt[String]('d', "db")
      .text("The storage path for the database (default is in-memory)")
      .validate(x => if Try(Paths.get(x)).isSuccess then success else failure(s"$x is an invalid path"))
      .action((x, c) => c.copy(dbPath = Option(Paths.get(x))))

    cmd("monitor")
      .text("Monitors open-source GitHub projects for potentially vulnerable applications")
      .action((_, c) => c.copy(mode = OperatingMode.Monitor))
      .children(
        opt[String]("token")
          .text("A fine-grained personal access GitHub token")
          .required()
          .action((x, c) => c.copy(ghToken = Option(x)))
      )

    cmd("review")
      .text("Presents findings of potentially vulnerable applications for manual review")
      .action((_, c) => c.copy(mode = OperatingMode.Review))

    cmd("report")
      .text("Generates a report of all verified findings")
      .action((_, c) => c.copy(mode = OperatingMode.Report))
  }

}
