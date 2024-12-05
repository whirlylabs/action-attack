package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.{Commit, Database, Finding, Repository}

import scala.util.{Using, Try}

trait RepositoryQueries {
  this: Database =>

  protected def createRepoIfNotExists(owner: String, name: String): Try[Int] = Try {
    Using.resource(connection.prepareStatement("INSERT OR IGNORE INTO repository(owner, name) VALUES(?, ?)")) { stmt =>
      stmt.setString(1, owner)
      stmt.setString(2, name)
      stmt.execute()
    }

    Using.resource(connection.prepareStatement("SELECT id FROM repository WHERE owner = ? AND name = ?")) { stmt =>
      stmt.setString(1, owner)
      stmt.setString(2, name)
      Using.resource(stmt.executeQuery()) { results =>
        if (results.next()) {
          results.getInt("id")
        } else {
          throw new Exception(s"Empty result set for $owner/$name!")
        }
      }
    }
  }

  /** @return
    *   all repositories with unvalidated and vulnerable commits.
    */
  protected def getRepositoriesWithUnvalidatedAndVulnerableCommits: List[Repository] = {
    Using.resource(
      connection
        .prepareStatement("""SELECT * FROM repository INNER JOIN commits on repository.id = commits.repository_id
            | INNER JOIN finding on finding.commit_sha = commits.sha
            | WHERE finding.validated_by_user = ?
            | AND commits.validated = ?
            |""".stripMargin)
    ) { stmt =>
      stmt.setBoolean(1, false)
      stmt.setBoolean(2, false)
      Using.resource(stmt.executeQuery())(Repository.fromResultSet)
    }
  }

  /** @param commit
    *   the commit object.
    * @return
    *   the associated repository if found.
    */
  def getRepository(commit: Commit): Option[Repository] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT id, owner, name FROM repository INNER JOIN commits ON repository.id = commits.repository_id WHERE commits.sha = ?"
      )
    ) { stmt =>
      stmt.setString(1, commit.sha)
      Using.resource(stmt.executeQuery())(Repository.fromResultSet).headOption
    }
  }

  /** @param id
    *   the repository id.
    * @return
    *   the associated repository if found.
    */
  def getRepository(id: Int): Option[Repository] = {
    Using.resource(connection.prepareStatement("SELECT id, owner, name FROM repository WHERE repository.id = ?")) {
      stmt =>
        stmt.setInt(1, id)
        Using.resource(stmt.executeQuery())(Repository.fromResultSet).headOption
    }
  }

  /** @return
    *   all repositories linked to validated and vulnerable commits.
    */
  protected def getRepositoriesWithValidatedAndVulnerableCommits: List[Repository] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM repository INNER JOIN commits ON repository.id = commits.repository_id INNER JOIN finding ON finding.commit_sha = commits.sha WHERE commits.validated = ? AND finding.valid = ?"
      )
    ) { stmt =>
      stmt.setBoolean(1, true)
      stmt.setBoolean(2, true)
      Using.resource(stmt.executeQuery())(Repository.fromResultSet)
    }
  }
}
