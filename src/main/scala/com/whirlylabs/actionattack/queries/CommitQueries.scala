package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.{Commit, Database, Repository}

import scala.util.{Try, Using}

trait CommitQueries {
  this: Database =>

  /** Adds a commit to the database with the intent to be scanned.
    *
    * @param owner
    *   the repository owner.
    * @param name
    *   the name of the repository.
    * @param commitHash
    *   the commit hash.
    */
  def queueCommit(owner: String, name: String, commitHash: String): Unit = {
    createRepoIfNotExists(owner, name).foreach { repositoryId =>
      Using.resource(
        connection
          .prepareStatement("INSERT OR IGNORE INTO commits(sha, scanned, validated, repository_id) VALUES (?,?,?,?)")
      ) { commitStmt =>
        commitStmt.setString(1, commitHash)
        commitStmt.setBoolean(2, false)
        commitStmt.setBoolean(3, false)
        commitStmt.setInt(4, repositoryId)
        commitStmt.execute()
      }
    }
  }

  /** @return
    *   the next unscanned commit in the repository if one is available.
    */
  def getNextCommitToScan: Option[Commit] = {
    Using.resource(connection.prepareStatement(s"SELECT * FROM commits WHERE scanned = ? LIMIT 1")) { stmt =>
      stmt.setBoolean(1, false)
      Using.resource(stmt.executeQuery())(Commit.fromResultSet(_).headOption)
    }
  }

  protected def getCommitsWithUnvalidatedAndVulnerableFindings(repository: Repository): List[Commit] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM repository INNER JOIN commits ON repository.id = commits.repository_id INNER JOIN finding ON finding.commit_sha = commits.sha WHERE repository.id = ? AND commits.validated = ? AND finding.validated_by_user = ?"
      )
    ) { stmt =>
      stmt.setInt(1, repository.id)
      stmt.setBoolean(2, false)
      stmt.setBoolean(3, false)
      Using.resource(stmt.executeQuery())(Commit.fromResultSet)
    }
  }

  def updateCommit(commitSha: String): Unit = {
    Using.resource(connection.prepareStatement("UPDATE commits SET validated = ? WHERE sha = ?")) { stmt =>
      stmt.setBoolean(1, true)
      stmt.setString(2, commitSha)
      stmt.execute()
    }
  }

  /** @return
    *   all commits linked to validated and vulnerable findings for the given repository.
    */
  protected def getCommitsWithValidatedAndVulnerableFindings(repository: Repository): List[Commit] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM repository INNER JOIN commits ON repository.id = commits.repository_id INNER JOIN finding ON finding.commit_sha = commits.sha WHERE repository.id = ? AND commits.validated = ? AND finding.valid = ?"
      )
    ) { stmt =>
      stmt.setInt(1, repository.id)
      stmt.setBoolean(2, true)
      stmt.setBoolean(3, true)
      Using.resource(stmt.executeQuery())(Commit.fromResultSet)
    }
  }

}
