package com.whirlylabs.actionattack

import org.jsoup.nodes.Document
import org.jsoup.nodes.Element
import org.jsoup.parser.Parser
import org.jsoup.Jsoup

import java.nio.file.{Files, Path, Paths}
import java.time.{LocalDateTime, LocalTime}
import java.time.format.DateTimeFormatter

class Report(private val db: Database) {

  private val outputPath: Path = {
    val timeString = Report.timeNow.format(DateTimeFormatter.ofPattern("HH-ss_dd-MM-yyyy"))
    Path.of(s"findings_$timeString.html")
  }

  def generateFindings(): Unit = {
    val outputStr = generateHtml(Map.empty)
    Files.write(outputPath, outputStr.getBytes)
  }

  private def generateHtml(findings: Map[Repository, Map[Commit, List[Finding]]]): String = {
    val docString =
      s"""<!DOCTYPE html>
         |<html>
         |<head>
         |${Report.header}
         |</head>
         |<body>
         |<header class="container"><h1>Action Attack Report</h1></header>
         |</body>
         |</html>
         |""".stripMargin
    val doc: Document = Jsoup.parse(docString, "", Parser.htmlParser)
    val body          = doc.body
    // Add contents
    val mainContainer = body
      .appendElement("main")
      .addClass("container")
    val findings = db.getValidatedFindingsForReport
    findingsToHtml(findings, mainContainer)
    // Footer
    doc.body
      .appendElement("footer")
      .addClass("container")
      .text("Whirly Labs (Pty) Ltd.")
    doc.outerHtml()
  }

  private def findingsToHtml(findings: Map[Repository, Map[Commit, List[Finding]]], mainContainer: Element): String = {
    ""
  }

}

object Report {

  private val timeNow = LocalDateTime.now()

  private def header =
    s"""<title>Action Attack Report: ${timeNow.format(DateTimeFormatter.ofPattern("HH-ss dd-MM-yyyy"))}</title>
       |<link
       |  rel="stylesheet"
       |  href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css"
       |>
       |""".stripMargin

}
