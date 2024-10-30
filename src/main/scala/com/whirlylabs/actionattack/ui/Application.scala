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
  line: Int,
  column: Int,
  kind: String,
  filePath: String,
  commitSha: String
) {
  def toTableString: Array[String] = {
    Array(message, line.toString, column.toString, kind, filePath, commitSha.substring(0, 9))
  }
}

case class ActionAttackFile(fileContent: String, offendingLine: Option[String])

case class Application(
  title: String,
  var should_quit: Boolean,
  resultSummaryList: RepositoryStatefulList,
  unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]],
  window: Point,
  enhanced_graphics: Boolean,
  db: Database,
  var activePane: SelectedPane
) {
  private val logger = LoggerFactory.getLogger(this.getClass)

  def on_up(): Unit =
    if this.activePane == SelectedPane.ResultsPane then this.resultSummaryList.previous()
    else this.resultSummaryList.prevTableItem()

  def on_down(): Unit =
    if this.activePane == SelectedPane.ResultsPane then this.resultSummaryList.next()
    else this.resultSummaryList.nextTableItem()

  def on_left(): Unit = {
    if this.activePane == SelectedPane.FindingsTablePane
    then this.activePane = SelectedPane.ResultsPane
  }

  def on_right(): Unit = {
    if this.activePane == SelectedPane.ResultsPane
    then this.activePane = SelectedPane.FindingsTablePane
  }

  def on_key(c: Char): Unit =
    c match {
      case 'q' => this.should_quit = true
      case 'Y' => // do something
      case 'y' =>
        if this.activePane == SelectedPane.FindingsTablePane then this.resultSummaryList.markFinding(true)
      case 'n' =>
        if this.activePane == SelectedPane.FindingsTablePane then this.resultSummaryList.markFinding(false)
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
      db,
      activePane = SelectedPane.ResultsPane
    )
  }
}
