package com.whirlylabs.actionattack

import org.jsoup.Jsoup
import org.jsoup.nodes.{Document, Element}
import org.jsoup.parser.Parser

import java.nio.file.{Files, Path}
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter

class Report(private val db: Database) {

  private val outputPath: Path = {
    val timeString = Report.timeNow.format(DateTimeFormatter.ofPattern("HH-ss_dd-MM-yyyy"))
    Path.of(s"findings_$timeString.html")
  }

  def generateFindings(): Unit = {
    val findings  = db.getValidatedFindingsForReport
    val outputStr = generateHtml(findings)
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

    findingsToHtml(findings, mainContainer)
    // Footer
    doc.body
      .appendElement("footer")
      .addClass("container")
      .text("Whirly Labs (Pty) Ltd.")
    doc.outerHtml()
  }

  private def findingsToHtml(findings: Map[Repository, Map[Commit, List[Finding]]], mainContainer: Element): Unit = {
    findings.foreach { case (repository, commitMap) =>
      val repositoryUrl  = s"https://github.com/${repository.owner}/${repository.name}"
      val repositoryCard = mainContainer.appendElement("article").attr("style", "margin-bottom: 75px;")
      repositoryCard.appendElement("header").text(s"${repository.owner}/${repository.name}")
      val repositoryContainer = repositoryCard.appendElement("div").addClass("container")
      commitMap.foreach { case (commit, findings) =>
        // We make no explicit divide by commit, the link will contain the url however
        val commitUrl = s"$repositoryUrl/blob/${commit.sha}"
        findings.zipWithIndex.foreach { case (finding, idx) =>
          // Finding heading
          val commitHeaderGroup = repositoryContainer.appendElement("hgroup")
          commitHeaderGroup.appendElement("h5").addClass("pico-color-zinc-100").text(finding.kind)
          commitHeaderGroup.appendElement("p").text(finding.message)
          // Code block if one exists
          val snippet   = finding.snippet.getOrElse("<no code snippet available>")
          val codeBlock = s"// ${finding.filepath}\n\n${finding.line}|$snippet"
          repositoryContainer.appendElement("pre").attr("style", "padding: 15px;").text(codeBlock)
          // Finding footer
          val commitFooterGroup = repositoryContainer.appendElement("footer")
          val codeUrl           = s"$commitUrl/${finding.filepath}#L${finding.line}"
          commitFooterGroup
            .appendElement("a")
            .addClass("contrast")
            .attr("href", codeUrl)
            .text("Show in GitHub")

          if (idx < findings.size - 1) repositoryContainer.appendElement("hr")
        }
      }
    }
  }

}

object Report {

  private val timeNow = LocalDateTime.now()

  private def header =
    s"""<title>Action Attack Report: ${timeNow.format(DateTimeFormatter.ofPattern("HH-ss dd-MM-yyyy"))}</title>
       |<link rel="stylesheet"  href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
       |<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.colors.min.css">
       |""".stripMargin

}
