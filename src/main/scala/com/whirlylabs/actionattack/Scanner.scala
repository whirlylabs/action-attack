package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.scan.yaml.{
  CommandInjectionScanner,
  GitHubActionsWorkflow,
  runScans,
  yamlToGHWorkflow
}
import org.slf4j.LoggerFactory

import java.io.File
import java.nio.file.{Files, Path}
import scala.util.{Failure, Success, Try}
import upickle.default.*

import scala.jdk.CollectionConverters.IteratorHasAsScala

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
              try {
                val findings = runScan(repoPath)
                db.storeResults(commit, findings)
              } catch {
                case e: Exception =>
                  logger.error("Exception occurred while running scan & storing results", e)
              } finally {
                repoPath.delete()
              }
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
    val targetDir = Files.createTempDirectory(s"action-attack-${repository.owner}-${repository.name}-")
    val repoUrl   = repository.toUrl
    val cloneCmd  = Seq("git", "clone", repoUrl.toString, targetDir.toAbsolutePath.toString, "--depth", "1")
    logger.debug(s"Cloning repository with '${cloneCmd.mkString(" ")}")
    val cloneProcess = ProcessBuilder(cloneCmd*).startBlocking
    if (cloneProcess.exitValue() != 0) {
      val msg = new String(cloneProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while cloning repository! Details: $msg")
    }
    val fetchCmd     = Seq("git", "fetch", "--depth", "1", "origin", commit.sha)
    val fetchProcess = ProcessBuilder(fetchCmd*).directory(targetDir.toFile).startBlocking
    if (fetchProcess.exitValue() != 0) {
      val msg = new String(fetchProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while fetching the target commit! Details: $msg")
    }
    val checkoutCmd     = Seq("git", "checkout", commit.sha)
    val checkoutProcess = ProcessBuilder(checkoutCmd*).directory(targetDir.toFile).startBlocking
    if (checkoutProcess.exitValue() != 0) {
      val msg = new String(checkoutProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while checking out to the target commit! Details: $msg")
    }
    targetDir
  }

  private def runScan(repositoryPath: Path): List[Finding] = {

    def isYAMLFile(path: Path): Boolean = {
      val fileName = path.getFileName.toString
      fileName.endsWith(".yml") || fileName.endsWith(".yaml")
    }

    def runInternal: List[Finding] = {
      // TODO: Scanners to run should be configurable
      lazy val scannersToRun = CommandInjectionScanner() :: Nil

      val githubPath = repositoryPath.resolve(".github").resolve("workflows")
      if (Files.exists(githubPath) && Files.isDirectory(githubPath)) {
        // Run through GitHub directory for YAML files
        val candidates = Files
          .walk(githubPath)
          .iterator()
          .asScala
          .filter(path => Files.isRegularFile(path) && isYAMLFile(path))
          .toList
        // Parse all yaml files and keep those that are workflow files
        val workflowFiles = candidates
          .flatMap { path =>
            yamlToGHWorkflow(Files.readString(path)) match {
              case Success(workflow) => Option(workflow)
              case Failure(e) if !path.getParent.equals(githubPath) =>
                logger.debug(
                  s"Unable to parse '$path' as a GitHub workflow file, however it's likely that it's not one",
                  e
                )
                None
              case Failure(e) =>
                logger.warn(s"Unable to parse '$path' as a GitHub workflow file", e)
                None
            }
          }
        // Run scans on these files
        workflowFiles.flatMap(runScans(_, scannersToRun))
      } else {
        Nil
      }
    }

    def runOctoscan: List[Finding] = {
      // Run scan with octoscan with suggested config
      val args = Seq(
        "octoscan",
        "scan",
        ".",
        "--disable-rules",
        "shellcheck,local-action",
        "--filter-triggers",
        "external",
        "--json"
      )
      logger.debug(s"Running scan with $args")
      val pb      = ProcessBuilder(args*).directory(repositoryPath.toFile)
      val process = pb.startBlocking
      val result  = new String(process.getInputStream.readAllBytes())
      logger.debug(s"Scan complete with exit code ${process.exitValue()}")
      val findings = read[List[Finding]](result)
      if (process.exitValue() == 0) {
        // This means no findings
        Nil
      } else if (process.exitValue() != 2) {
        // This means error
        logger.error(result)
        Nil
      } else {
        logger.info(s"Scan resulted in ${findings.size} findings")
        findings
      }
    }

    runOctoscan ++ runInternal
  }

  override def close(): Unit = {
    logger.info("Stopping scanner...")
    running = false
  }

  implicit class ProcessExt(pb: ProcessBuilder) {

    /** A version of [[ProcessBuilder.start]] that is blocking
      * @return
      *   the process once it's complete
      */
    def startBlocking: Process = {
      val p = pb.start()
      while (p.isAlive) { Thread.sleep(100) }
      p
    }

  }

  implicit class PathExt(pb: Path) {

    /** A version of [[ProcessBuilder.start]] that is blocking
      *
      * @return
      *   the process once it's complete
      */
    def delete(): Unit = deleteFileOrDir(pb.toFile)

    private def deleteFileOrDir(file: File): Unit = {
      Option(file.listFiles).foreach { contents =>
        contents.filterNot(f => Files.isSymbolicLink(f.toPath)).foreach(deleteFileOrDir)
      }
      file.delete
    }

  }

}
