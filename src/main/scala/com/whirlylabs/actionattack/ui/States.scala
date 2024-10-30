package com.whirlylabs.actionattack.ui

import com.whirlylabs.actionattack.*
import org.slf4j.LoggerFactory
import tui.*
import tui.widgets.{ListWidget, TableWidget}

import java.util.concurrent.ForkJoinPool
import java.util.concurrent.ForkJoinPool.ManagedBlocker
import scala.collection.mutable
import scala.util.{Failure, Success, Try}

enum SelectedPane:
  case ResultsPane, FindingsTablePane

case class TableItemsState(state: TableWidget.State, items: mutable.ArrayDeque[TableItem]) {
  def next(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i >= this.items.length - 1) 0 else i + 1
      case None    => 0
    }
    this.state.select(Some(i))
  }

  def previous(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i == 0) this.items.length - 1 else i - 1
      case None    => 0
    }

    this.state.select(Some(i))
  }
}

case class RepositoryStatefulList(
  state: ListWidget.State,
  items: mutable.ArrayDeque[Repository],
  unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
  token: String,
  db: Database
) {
  val DOWNLOADING_FILE = "DOWNLOADING_FILE"
  val ERROR_FILE       = "Something went wrong"

  private val logger                                        = LoggerFactory.getLogger(this.getClass)
  private val tableStates: Map[Repository, TableItemsState] = generateTableStates()
  private var currentFile: ActionAttackFile                 = updateFile()

  private def generateTableStates(): Map[Repository, TableItemsState] = {
    unvalidatedFindings.map((repository, commit) =>
      val findingsStateList = commit
        .flatMap((_, findings) =>
          findings.map(finding =>
            TableItem(
              finding.id,
              finding.message,
              finding.line,
              finding.column,
              finding.kind,
              finding.filepath,
              finding.commitSha
            )
          )
        )
        .toList

      val tableItemsState =
        TableItemsState(TableWidget.State(selected = Some(0)), mutable.ArrayDeque.from(findingsStateList))

      (repository, tableItemsState)
    )
  }

  def nextTableItem(): Unit = {
    val repo                  = this.items(getRepositoryIdx)
    val currentTableItemState = this.tableStates(repo)

    val i = currentTableItemState.state.selected match {
      case Some(i) => if (i >= currentTableItemState.items.length) 0 else i + 1
      case None    => 0
    }

    this.tableStates(repo).state.select(Some(i))
    this.updateFile()
  }

  def prevTableItem(): Unit = {
    val repo                  = this.items(getRepositoryIdx)
    val currentTableItemState = this.tableStates(repo)

    val i = currentTableItemState.state.selected match {
      case Some(i) => if (i == 0) currentTableItemState.items.length - 1 else i - 1
      case None    => 0
    }

    this.tableStates(repo).state.select(Some(i))
    this.updateFile()
  }

  def getCurrentTableSelectedState: TableItemsState = this.tableStates(this.items(getRepositoryIdx))

  private def firstTableItem(): Unit = {
    val repo = this.items(getRepositoryIdx)
    this.tableStates(repo).state.select(Some(0))
  }

  def next(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i >= this.items.length - 1) 0 else i + 1
      case None    => 0
    }
    this.state.select(Some(i))
    this.updateFile()
  }

  def previous(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i == 0) this.items.length - 1 else i - 1
      case None    => 0
    }
    this.state.select(Some(i))
    this.updateFile()
  }

  def getCurrentFile: ActionAttackFile = {
    this.currentFile
  }

  def markFinding(valid: Boolean): Unit = {
    val currentRepo    = this.items(getRepositoryIdx)
    val currentFinding = this.tableStates(currentRepo).items(getTableStateIdx)

    db.updateFinding(currentFinding.findingId, valid)

    if (this.tableStates(currentRepo).items.length > 1) {
      this.tableStates(currentRepo).items.remove(getTableStateIdx)
    } else {
      db.updateCommit(currentFinding.commitSha)
      this.items.remove(getRepositoryIdx)
    }

    updateFile()
  }
  import scala.concurrent.{Future, ExecutionContext}
  import ExecutionContext.Implicits.global

  private def getFile: Future[ActionAttackFile] = Future {
    val repo     = this.items(getRepositoryIdx)
    val findings = this.tableStates(repo).items(getTableStateIdx)

    val fileContent =
      getFileFromGh(repo, findings.commitSha, findings.filePath)
    ActionAttackFile(fileContent.getOrElse(""), Some(findings.line.toString))
  }

  private def updateFile(): ActionAttackFile = {
    this.currentFile = ActionAttackFile(DOWNLOADING_FILE, None)

    getFile.onComplete {
      case Success(file) =>
        this.currentFile = file
      case Failure(err) =>
        this.currentFile = ActionAttackFile(s"$ERROR_FILE: ${err.getCause}", None)
    }

    this.currentFile
  }

  private def getFileFromGh(repository: Repository, commitSha: String, filePath: String): Option[String] = {
    val repositoryUrl = s"https://raw.githubusercontent.com/${repository.owner}/${repository.name}"
    val commitUrl     = s"$repositoryUrl/$commitSha/$filePath"

    Try { requests.get(commitUrl) } match {
      case Success(response) =>
        Some(response.data.toString)
      case Failure(exception) =>
        logger.error("something went wrong: ", exception)
        None
    }
  }

  /** @return
    *   index of selected repository
    */
  private def getRepositoryIdx: Int = {
    this.state.selected match {
      case Some(idx) => idx
      case None      => 0
    }
  }

  /** @return
    *   index of current table state
    */
  private def getTableStateIdx: Int = {
    this.tableStates(this.items(getRepositoryIdx)).state.selected match {
      case Some(idx) => idx
      case None      => 0
    }
  }
}

object RepositoryStatefulList {
  def with_items(
    items: Array[Repository],
    unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
    token: String,
    db: Database
  ): RepositoryStatefulList =
    val startingItem = if items.nonEmpty then Some(0) else None
    RepositoryStatefulList(
      state = ListWidget.State(selected = startingItem),
      items = mutable.ArrayDeque.from(items),
      unvalidatedFindings,
      token,
      db
    )
}
