package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory
import scopt.OptionParser

import java.nio.file.{Path, Paths}
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

    opt[String]('o', "output")
      .text("The storage path for the database (default is in-memory)")
      .validate(x => if Try(Paths.get(x)).isSuccess then success else failure(s"$x is an invalid path"))
      .action((x, c) => c.copy(dbPath = Option(Paths.get(x))))

    cmd("monitor")
      .text("Monitors open-source GitHub projects for potentially vulnerable applications")
      .action((_, c) => c.copy(mode = OperatingMode.Monitor))
      .children(
        opt[String]("token")
          .text("A fine-grained personal access GitHub token (will alternatively look for token under `.env`)")
          .action((x, c) => c.copy(ghToken = Option(x)))
      )

    cmd("scan")
      .text("Scans the provided GitHub repository for potentially vulnerable workflows")
      .action((_, c) => c.copy(mode = OperatingMode.Scan))
      .children(
        opt[String]("owner")
          .text("The owner of the repository")
          .action((x, c) => c.copy(owner = Option(x))),
        opt[String]("repo")
          .text("The name of the repository")
          .action((x, c) => c.copy(repo = Option(x))),
        opt[String]("commitHash")
          .text("The commit hash to scan")
          .action((x, c) => c.copy(commitSha = Option(x)))
      )

    cmd("review")
      .text("Presents findings of potentially vulnerable applications for manual review")
      .action((_, c) => c.copy(mode = OperatingMode.Review))

    cmd("report")
      .text("Generates a report of all verified findings")
      .action((_, c) => c.copy(mode = OperatingMode.Report))
  }

}
