package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory

import java.nio.file.Path
import scala.util.{Failure, Success, Try}

class Scanner(db: Database) extends Runnable, AutoCloseable {

  private val logger = LoggerFactory.getLogger(getClass)

  @volatile private var running: Boolean = true

  override def run(): Unit = {
    logger.info("Running scanning jobs in the background...")
    while (running) {
      db.getNextCommitToScan.foreach { commit =>
        db.getRepository(commit).foreach { repository =>
          logger.info(s"Running scan on $repository:${commit.sha}")
          cloneRepo(repository, commit) match {
            case Success(repoPath) =>
              val findings = runScan(repoPath)
              db.storeResults(commit, findings)
            case Failure(exception) =>
              logger.error(s"Unable to clone $repository:${commit.sha}", exception)
          }

        }
      }
      // Avoid overburdening the database
      Thread.sleep(1000)
    }
  }

  private def cloneRepo(repository: Repository, commit: Commit): Try[Path] = Try {
    // TODO: Pull repository to temp dir (remember to clean up after scan)
    Path.of("")
  }

  private def runScan(repositoryPath: Path): List[String] = {
    // Run scan with octoscan with suggested config
    val args = Seq(
      "octoscan",
      "scan",
      repositoryPath.toAbsolutePath.toString,
      "--disable-rules",
      "shellcheck,local-action",
      "--filter-triggers",
      "external"
    )
    logger.debug(s"Running scan with $args")
    val pb      = ProcessBuilder(args*)
    val process = pb.start()
    val result  = new String(process.getInputStream.readAllBytes())
    logger.debug(s"Scan complete with exit code ${process.exitValue()}")
    if (process.exitValue() != 0) {
      logger.error(result)
      Nil
    } else {
      result.split("\n").map(_.trim).toList
    }
  }

  override def close(): Unit = {
    logger.info("Stopping scanner...")
    running = false
  }

}
