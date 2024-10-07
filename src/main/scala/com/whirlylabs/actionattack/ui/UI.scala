package com.whirlylabs.actionattack.ui

import tui.*
import tui.widgets.*

object UI {
  def draw(f: Frame, app: Application): Unit = {
    val mainLayout =
      Layout(constraints = Array(Constraint.Percentage(20), Constraint.Min(0)), direction = Direction.Horizontal)
        .split(f.size)
    val rhsLayout =
      Layout(constraints = Array(Constraint.Percentage(30), Constraint.Percentage(70)), direction = Direction.Vertical)
        .split(mainLayout(1))

    drawResultSummaryList(f, app, mainLayout(0))
    drawResultTable(f, app, rhsLayout(0))
    drawFileRender(f, app, rhsLayout(1))
  }

  def drawResultSummaryList(f: Frame, app: Application, area: Rect): Unit = {
    val title      = Spans.from(Span.styled("Result Summary", Style.DEFAULT.addModifier(Modifier.BOLD)))
    val titleBlock = BlockWidget(borders = Borders.ALL, title = Some(title))

    val items: Array[ListWidget.Item] = app.resultSummaryList.items
      .map(i => ListWidget.Item(content = Text.nostyle(i.toString)))
      .toArray

    val highlightStyle =
      if app.activePane == SelectedPane.ResultsPane then Style.DEFAULT.addModifier(Modifier.BOLD).fg(Color.Green)
      else Style.DEFAULT

    val highlightSymbol =
      if app.activePane == SelectedPane.ResultsPane then Some("> ")
      else Some("")

    val tasks = ListWidget(
      items = items,
      block = Some(titleBlock),
      highlightStyle = highlightStyle,
      highlightSymbol = highlightSymbol
    )

    f.renderStatefulWidget(tasks, area)(app.resultSummaryList.state)
  }

  def drawResultTable(f: Frame, app: Application, area: Rect): Unit = {
    val title      = Spans.from(Span.styled("Findings", Style.DEFAULT.addModifier(Modifier.BOLD)))
    val titleBlock = BlockWidget(borders = Borders.ALL, title = Some(title))

    val headers: Array[Array[String]] = Array(Array("MESSAGE", "LINE", "COLUMN", "KIND", "FILEPATH", "SHA"))

    val findings = app.resultSummaryList.getCurrentTableSelectedState.items

    val rows = findings.map { item =>
      val itemString = item.toTableString
      val height     = itemString.map(_.count(_ == '\n')).maxOption.getOrElse(0) + 1
      val cells      = itemString.map(c => TableWidget.Cell(Text.nostyle(c)))

      TableWidget.Row(cells, height = height, bottomMargin = 1)
    }.toArray

    val header_cells =
      (headers(0)).map(h => TableWidget.Cell(Text.nostyle(h), style = Style(fg = Some(Color.Red))))
    val header = TableWidget.Row(cells = header_cells, style = Style(bg = Some(Color.Blue)))

    val highlightStyle =
      if app.activePane == SelectedPane.FindingsTablePane then Style.DEFAULT.fg(Color.Green)
      else Style.DEFAULT

    val highlightSymbol =
      if app.activePane == SelectedPane.FindingsTablePane then Some(">")
      else Some("")

    val tableWidget = TableWidget(
      block = Some(titleBlock),
      widths = Array(
        Constraint.Percentage(50), // Message Column
        Constraint.Percentage(5),  // LINE Column
        Constraint.Percentage(5),  // COLUMN Column
        Constraint.Percentage(15), // KIND Column
        Constraint.Percentage(15), // FILEPATH Column
        Constraint.Percentage(10)  // SHA Column
      ),
      highlightSymbol = highlightSymbol,
      highlightStyle = highlightStyle,
      header = Some(header),
      rows = rows
    )

    f.renderStatefulWidget(tableWidget, area)(app.resultSummaryList.getCurrentTableSelectedState.state)
  }

  def drawFileRender(f: Frame, app: Application, area: Rect): Unit = {
    val title      = Spans.from(Span.styled("FILE", Style.DEFAULT.addModifier(Modifier.BOLD)))
    val titleBlock = BlockWidget(borders = Borders.ALL, title = Some(title))

    val currentFile = app.resultSummaryList.getCurrentFile
    val splitLines  = currentFile.fileContent.split("\n")

    var highlightNextLine = false

    val lines = Text.fromSpans(
      splitLines.zipWithIndex.map((line, index) =>
        if (highlightNextLine) {
          highlightNextLine = false
          Spans.styled(line, Style.DEFAULT.fg(Color.Red).addModifier(Modifier.BOLD))
        } else if (index != (currentFile.offendingLine.toInt - 1)) {
          Spans.nostyle(line)
        } else if (index == currentFile.offendingLine.toInt - 1 && line.strip == "{") {
          highlightNextLine = true
          Spans.nostyle(line)
        } else {
          Spans.styled(line, Style.DEFAULT.fg(Color.Red).addModifier(Modifier.BOLD))
        }
      )*
    )

    // Roughly calculates the height of one line, and scrolls when the offending line is > number of lines visible in the
    // file block
    val lineHeight      = (lines.height / splitLines.size)
    val numLinesInBlock = area.height / lineHeight

    val scrollLine =
      if currentFile.offendingLine.toInt > numLinesInBlock then (currentFile.offendingLine.toInt - numLinesInBlock + 10)
      else 0

    val pgWidget =
      ParagraphWidget(text = lines, block = Some(titleBlock), alignment = Alignment.Left, scroll = (scrollLine, 0))

    f.renderWidget(pgWidget, area)
  }
}
