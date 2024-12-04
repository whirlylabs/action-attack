package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.{Commit, Database, Finding, Repository}

import scala.util.Using

trait FindingQueries { this: Database =>

  /** Store results from a scan.
    *
    * @param commit
    *   the commit that has been scanned.
    * @param results
    *   the finding descriptions.
    */
  def storeResults(commit: Commit, results: List[Finding]): Unit = {
    results.foreach { case Finding(_, _, _, _, message, filepath, line, column, columnEnd, snippet, kind) =>
      Using.resource(connection.prepareStatement("""
                                                   |INSERT INTO finding(
                                                   | commit_sha,
                                                   | valid,
                                                   | validatedByUser,
                                                   | message,
                                                   | filepath,
                                                   | line,
                                                   | column,
                                                   | column_end,
                                                   | snippet,
                                                   | kind
                                                   |) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                                   |""".stripMargin)) { stmt =>
        stmt.setString(1, commit.sha)
        stmt.setBoolean(2, false)
        stmt.setBoolean(3, false)
        stmt.setString(4, message)
        stmt.setString(5, filepath)
        stmt.setInt(6, line)
        stmt.setInt(7, column)
        stmt.setInt(8, columnEnd)
        stmt.setString(9, snippet.orNull)
        stmt.setString(10, kind)
        stmt.execute()
      }
    }
    Using.resource(connection.prepareStatement("UPDATE commits SET scanned = ? WHERE sha = ?")) { stmt =>
      stmt.setBoolean(1, true)
      stmt.setString(2, commit.sha)
      stmt.execute()
    }
  }

  /** @return
    *   all commits linked to validated and vulnerable findings for the given repository.
    */
  protected def getVulnerableFindings(commit: Commit): List[Finding] = {
    if (!commit.validated) {
      logger.warn(
        s"${commit.sha} with repository ID ${commit.repositoryId} has not been validated, returning empty result..."
      )
      Nil
    } else {
      Using.resource(
        connection.prepareStatement(
          "SELECT * FROM finding INNER JOIN commits ON finding.commit_sha = commits.sha WHERE finding.valid = ? AND commits.sha = ?"
        )
      ) { stmt =>
        stmt.setBoolean(1, true)
        stmt.setString(2, commit.sha)
        Using.resource(stmt.executeQuery())(Finding.fromResultSet)
      }
    }
  }

  protected def getUnvalidatedFindings(commit: Commit): List[Finding] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM finding INNER JOIN commits ON finding.commit_sha = commits.sha WHERE finding.validated_by_user = ? AND commits.sha = ?"
      )
    ) { stmt =>
      stmt.setBoolean(1, false)
      stmt.setString(2, commit.sha)
      Using.resource(stmt.executeQuery())(Finding.fromResultSet)
    }
  }

  def getUnvalidatedFindingsForReview: Map[Repository, Map[Commit, List[Finding]]] = {
    getRepositoriesWithUnvalidatedAndVulnerableCommits.map { repository =>
      repository -> getCommitsWithUnvalidatedAndVulnerableFindings(repository).map { commit =>
        commit -> getUnvalidatedFindings(commit)
      }.toMap
    }.toMap
  }

  /** Updates finding validated by user via the TUI
    *
    * @param findingId
    *   id of the finding that needs to be updated
    * @param valid
    *   whether the finding is valid or not (determined by user)
    */
  def updateFinding(findingId: Int, valid: Boolean): Unit = {
    Using.resource(connection.prepareStatement("UPDATE finding SET valid = ?, validated_by_user = ? WHERE id = ?")) {
      stmt =>
        stmt.setBoolean(1, valid)
        stmt.setBoolean(2, true)
        stmt.setInt(3, findingId)
        stmt.execute()
    }
  }

  /** @return
    *   all validated findings that are true positives, mapped by their repository and commit.
    */
  def getValidatedFindingsForReport: Map[Repository, Map[Commit, List[Finding]]] = {
    // Is there a more efficient way to do this? Possibly...
    getRepositoriesWithValidatedAndVulnerableCommits.map { repository =>
      repository -> getCommitsWithValidatedAndVulnerableFindings(repository).map { commit =>
        commit -> getVulnerableFindings(commit)
      }.toMap
    }.toMap
  }

}
