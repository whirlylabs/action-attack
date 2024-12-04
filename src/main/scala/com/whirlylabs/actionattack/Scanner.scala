package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.Scanner.ProcessExt
import com.whirlylabs.actionattack.scan.{ExternalActionsScanner, WorkflowAction}
import com.whirlylabs.actionattack.scan.yaml.{
  CommandInjectionScanner,
  GitHubActionsWorkflow,
  runScans,
  yamlToGHWorkflow
}
import org.slf4j.LoggerFactory
import org.yaml.snakeyaml.scanner.ScannerException
import upickle.default.*

import java.io.File
import java.nio.file.{Files, Path}
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.util.{Failure, Success, Try}

class Scanner(db: Database) extends Runnable, AutoCloseable {

  private val logger = LoggerFactory.getLogger(getClass)

  @volatile private var running: Boolean = true

  override def run(): Unit = {
    logger.info("Running scanning jobs in the background...")
    while (running) {
      db.getUnscannedActions match {
        case unscannedAction :: _ =>
          logger.info(s"Running scan on external action ")
          ExternalActionsScanner.scanExternalAction(db, unscannedAction)
        case Nil =>
          db.getNextCommitToScan.foreach { commit =>
            db.getRepository(commit).foreach { repository =>
              logger.info(s"Running scan on $repository:${commit.sha}")
              Scanner.cloneRepo(repository, commit.sha) match {
                case Success(repoPath) =>
                  try {
                    val workflowFiles = getWorkflowFiles(repoPath)
                    if (!shouldScanPluginRepos(workflowFiles)) {
                      val findings = runScan(repoPath, commit, workflowFiles)
                      db.storeResults(commit, findings)
                    } else {
                      logger.info(s"$repository @ $commit contains unscanned external actions, returning later...")
                    }
                  } catch {
                    case e: Exception =>
                      logger.error("Exception occurred while running scan & storing results", e)
                  } finally {
                    repoPath.delete()
                  }
                case Failure(exception) =>
                  logger.error(s"Unable to clone $repository:${commit.sha}", exception)
                  db.storeResults(commit, Nil)
              }
            }
          }
      }
      // Avoid overburdening the database
      Thread.sleep(1000)
    }
  }

  private def shouldScanPluginRepos(workflowFiles: List[(Path, GitHubActionsWorkflow)]): Boolean = {
    ExternalActionsScanner
      .fetchActionsNames(workflowFiles.map(_._2))
      .foreach { case WorkflowAction(owner, name, version) => db.queueAction(owner, name, version) }

    db.getUnscannedActions.nonEmpty
  }

  private def getWorkflowFiles(repositoryPath: Path): List[(Path, GitHubActionsWorkflow)] = {
    def isYAMLFile(path: Path): Boolean = {
      val fileName = path.getFileName.toString
      fileName.endsWith(".yml") || fileName.endsWith(".yaml")
    }

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
      val a = candidates
        .flatMap { path =>
          yamlToGHWorkflow(Files.readString(path)) match {
            case Success(workflow) =>
              Option(path -> workflow)
            case Failure(_: ScannerException) =>
              logger.warn(s"Unable to parse '$path', it appears to be an invalid YAML file")
              None
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
      a
    } else {
      List.empty
    }
  }

  private def runScan(
    repositoryPath: Path,
    commit: Commit,
    workflowFiles: List[(Path, GitHubActionsWorkflow)]
  ): List[Finding] = {
    def runInternal: List[Finding] = {
      // TODO: Scanners to run should be configurable
      lazy val scannersToRun = CommandInjectionScanner() :: Nil

      val githubPath = repositoryPath.resolve(".github").resolve("workflows")
      if (Files.exists(githubPath) && Files.isDirectory(githubPath)) {
        // TODO: Re-check this filtering once we have plugin vulnerability scanning done
        // Run scans on these files, filtering out files that don't have vulnerable triggers
        workflowFiles.filter(x => x._2.on.vulnerableTriggers.nonEmpty).flatMap { case (path, actionsFile) =>
          val relativePath = repositoryPath.relativize(path).toString
          runScans(actionsFile, scannersToRun, commit.sha, relativePath)
        }
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

object Scanner {

  private val logger = LoggerFactory.getLogger(getClass)

  /** @param repository
    *   the Git repository
    * @param checkoutDestination
    *   the `git checkout` destination. Can be an SHA, tag, branch, etc.
    * @param fetchTags
    *   if the Git tags should be fetched. Necessary if `checkoutDestination` is a branch or tag.
    * @return
    *   the temporary path this repository is checked out to if successful.
    */
  def cloneRepo(repository: Repository, checkoutDestination: String, fetchTags: Boolean = false): Try[Path] = Try {
    val targetDir = Files.createTempDirectory(s"action-attack-${repository.owner}-${repository.name}-")
    val repoUrl   = repository.toUrl
    val cloneCmd  = Seq("git", "clone", repoUrl.toString, targetDir.toAbsolutePath.toString, "--depth", "1")
    logger.debug(s"Cloning repository with '${cloneCmd.mkString(" ")}")
    val cloneProcess = ProcessBuilder(cloneCmd*).startBlocking
    if (cloneProcess.exitValue() != 0) {
      val msg = new String(cloneProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while cloning repository! Details: $msg")
    }
    val fetchCmd     = Seq("git", "fetch", "--depth", "1", "origin", checkoutDestination)
    val fetchProcess = ProcessBuilder(fetchCmd*).directory(targetDir.toFile).startBlocking
    if (fetchProcess.exitValue() != 0) {
      val msg = new String(fetchProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while fetching the target commit! Details: $msg")
    }
    if (fetchTags) {
      val fetchTagsCmd     = Seq("git", "fetch", "--tags")
      val fetchProcessTags = ProcessBuilder(fetchTagsCmd*).directory(targetDir.toFile).startBlocking
      if (fetchProcessTags.exitValue() != 0) {
        val msg = new String(fetchProcessTags.getErrorStream.readAllBytes())
        throw new RuntimeException(s"Error occurred while fetching the target commit! Details: $msg")
      }
    }
    val checkoutCmd = Seq("git", "checkout", checkoutDestination)
    logger.debug(s"Checkout cmd: ${checkoutCmd.mkString(" ")}")
    val checkoutProcess = ProcessBuilder(checkoutCmd*).directory(targetDir.toFile).startBlocking
    if (checkoutProcess.exitValue() != 0) {
      val msg = new String(checkoutProcess.getErrorStream.readAllBytes())
      throw new RuntimeException(s"Error occurred while checking out to the target commit! Details: $msg")
    }
    targetDir
  }

  implicit class ProcessExt(pb: ProcessBuilder) {

    /** A version of [[ProcessBuilder.start]] that is blocking
      *
      * @return
      *   the process once it's complete
      */
    def startBlocking: Process = {
      val p = pb.start()
      while (p.isAlive) {
        Thread.sleep(100)
      }
      p
    }

  }

}
