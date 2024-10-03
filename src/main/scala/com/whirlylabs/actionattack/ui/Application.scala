package com.whirlylabs.actionattack.ui

import com.whirlylabs.actionattack.*
import com.whirlylabs.actionattack.scan.yaml.YamlParser
import org.slf4j.LoggerFactory
import tui.*
import tui.widgets.{ListWidget, TableWidget}

import scala.collection.mutable
import scala.reflect.ClassTag
import scala.util.{Failure, Success, Try}

case class TableItem(
  findingId: Int,
  message: String,
  line: String,
  column: String,
  kind: String,
  filePath: String,
  commitSha: String
) {
  def toTableString: Array[String] = {
    Array(message, line, column, kind, filePath, commitSha.substring(0, 9))
  }
}

case class ActionAttackFile(fileContent: String, offendingLine: String)

case class RepositoryStatefulList(
  state: ListWidget.State,
  items: mutable.ArrayDeque[Repository],
  unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
  token: String,
  db: Database
) {
  private val logger                             = LoggerFactory.getLogger(this.getClass)
  private var currentTableItems: List[TableItem] = updateTable()
  private var currentFile: ActionAttackFile      = updateFile()

  def next(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i >= this.items.length - 1) 0 else i + 1
      case None    => 0
    }
    this.state.select(Some(i))
    this.updateTable()
    this.updateFile()
  }

  def previous(): Unit = {
    val i = this.state.selected match {
      case Some(i) => if (i == 0) this.items.length - 1 else i - 1
      case None    => 0
    }
    this.state.select(Some(i))
    this.updateTable()
    this.updateFile()
  }

  def getTableItems: List[TableItem] = {
    this.currentTableItems
  }

  def getCurrentFile: ActionAttackFile = {
    this.currentFile
  }

  def markFinding(valid: Boolean): Unit = {
    val currentFinding = this.currentTableItems.head
    db.updateFinding(currentFinding.findingId, valid)

    if this.currentTableItems.size > 1 then currentTableItems = this.currentTableItems.tail
    else
      db.updateCommit(currentFinding.commitSha)
      this.state.select(Option(getIdx + 1))
      currentTableItems = updateTable()

    updateFile()
  }

  private def updateFile(): ActionAttackFile = {
    if this.currentTableItems.isEmpty then null
    else
      val fileContent =
        getFileFromGh(this.items(getIdx), this.currentTableItems.head.commitSha, this.currentTableItems.head.filePath)
      this.currentFile = ActionAttackFile(fileContent.getOrElse(""), this.currentTableItems.head.line)
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

  private def updateTable(): List[TableItem] = {
    this.currentTableItems = this.unvalidatedFindings
      .get(this.items(getIdx))
      .map { repository =>
        repository.keys.flatMap { commit =>
          repository(commit).map { finding =>
            TableItem(
              finding.id,
              finding.message,
              finding.line.toString,
              finding.column.toString,
              finding.kind,
              finding.filepath,
              commit.sha
            )
          }
        }
      }
      .toList
      .flatten
      .sortBy(x => (x.line, x.column))

    this.currentTableItems
  }

  private def getIdx: Int = {
    this.state.selected match {
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

case class Application(
  title: String,
  var should_quit: Boolean,
  resultSummaryList: RepositoryStatefulList,
  unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
  window: Point,
  enhanced_graphics: Boolean,
  db: Database
) {
  private var currentFilePath = ""

  def on_up(): Unit =
    this.resultSummaryList.previous()

  def on_down(): Unit =
    this.resultSummaryList.next()

  def on_key(c: Char): Unit =
    c match {
      case 'q' => this.should_quit = true
      case 'Y' => // do something
      case 'y' => this.resultSummaryList.markFinding(true)
      case 'n' => this.resultSummaryList.markFinding(false)
      case 'N' => // do something
      case _   => ()
    }
}

object Application {
  private val logger = LoggerFactory.getLogger(getClass)

  def apply(
    title: String,
    enhanced_graphics: Boolean,
    db: Database,
    unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
    token: String
  ): Application = {
    new Application(
      title = title,
      should_quit = false,
      resultSummaryList =
        RepositoryStatefulList.with_items(unvalidatedFindings.keys.toArray, unvalidatedFindings, token, db),
      unvalidatedFindings = unvalidatedFindings,
      window = Point(0.0, 20.0),
      enhanced_graphics,
      db
    )
  }
}
