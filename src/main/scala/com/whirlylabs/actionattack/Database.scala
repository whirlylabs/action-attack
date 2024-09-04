package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.Database.FALSE
import org.slf4j.LoggerFactory

import java.nio.file.Path
import java.sql.{Connection, DriverManager, ResultSet, SQLException}
import scala.collection.mutable
import scala.compiletime.uninitialized
import java.net.{URI, URL}
import scala.util.{Try, Using}

class Database(location: Option[Path] = None) extends AutoCloseable {

  private val logger = LoggerFactory.getLogger(getClass)

  private val url = location match {
    case Some(path) => s"jdbc:sqlite:$path"
    case None       => "jdbc:sqlite::memory:"
  }
  private var connection: Connection = uninitialized

  sys.addShutdownHook {
    this.close()
  }

  try {
    connection = DriverManager.getConnection(url)
    logger.debug(s"Using database URL $url")
    logger.info("Connected to the SQLite database.")

    Using.resource(connection.createStatement()) { statement =>
      logger.debug("Initializing schema")
      Database.schema.foreach { stmt =>
        statement.execute(stmt)
      }
    }
  } catch {
    case e: SQLException => logger.error("Exception occurred while executing SQL statement", e)
  }

  override def close(): Unit = {
    if (connection != null && !connection.isClosed) {
      logger.info("Closing the database connection...")
      connection.close()
    }
    logger.info("Good-bye!")
  }

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
    Using.resource(connection.createStatement()) { stmt =>
      Using.resource(stmt.executeQuery(s"SELECT * FROM commits WHERE scanned = $FALSE LIMIT 1")) { results =>
        Commit.fromResultSet(results).headOption
      }
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

  /** Store results from a scan.
    * @param commit
    *   the commit that has been scanned.
    * @param results
    *   the finding descriptions.
    */
  def storeResults(commit: Commit, results: List[String]): Unit = {
    results.foreach { description =>
      Using.resource(
        connection.prepareStatement("INSERT INTO finding(commit_sha, description, valid) VALUES(?, ?, ?)")
      ) { stmt =>
        stmt.setString(1, commit.sha)
        stmt.setString(2, description)
        stmt.setBoolean(3, false)
        stmt.execute()
      }
    }
  }

  private def createRepoIfNotExists(owner: String, name: String): Try[Int] = Try {
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

}

object Database {

  val TRUE: Int  = 1
  val FALSE: Int = 0

  val schema: List[String] = List(
    "CREATE TABLE IF NOT EXISTS repository (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, name TEXT, UNIQUE(owner, name))",
    "CREATE TABLE IF NOT EXISTS commits (sha TEXT PRIMARY KEY, scanned BOOLEAN, validated BOOLEAN, repository_id INTEGER, FOREIGN KEY(repository_id) REFERENCES repository(id))",
    "CREATE TABLE IF NOT EXISTS finding (id INTEGER PRIMARY KEY AUTOINCREMENT, commit_sha TEXT, description TEXT, valid BOOLEAN, FOREIGN KEY(commit_sha) REFERENCES commits(commit_sha))"
  )

}

/** A GitHub repository.
  *
  * @param id
  *   the repository ID.
  * @param owner
  *   the owner of the repository.
  * @param name
  *   the name of the repository.
  */
case class Repository(id: Int, owner: String, name: String) {

  /** @return
    *   the GitHub URL to the repository.
    */
  def toUrl: URL = URI(s"https://github.com/$owner/$name").toURL

  override def toString: String = s"$owner/$name"

}

/** A single commit from a repository.
  *
  * @param sha
  *   the commit hash.
  * @param scanned
  *   true if the commit has been scanned for vulnerabilities.
  * @param validated
  *   true if the scan's findings have been validated.
  * @param repositoryId
  *   the corresponding repository's ID.
  */
case class Commit(sha: String, scanned: Boolean, validated: Boolean, repositoryId: Int)

/** A single finding from a scan for a commit.
  *
  * @param id
  *   the finding ID.
  * @param commitSha
  *   the related commit.
  * @param description
  *   the finding description.
  * @param valid
  *   if the finding is valid. This field is only considered if the related commit has been validated.
  */
case class Finding(id: Int, commitSha: String, description: String, valid: Boolean)

object Repository {

  def fromResultSet(rs: ResultSet): List[Repository] = {
    val xs = mutable.ListBuffer.empty[Repository]
    while (rs.next()) {
      Repository(id = rs.getInt("id"), owner = rs.getString("owner"), name = rs.getString("name"))
    }
    xs.toList
  }

}

object Commit {

  def fromResultSet(rs: ResultSet): List[Commit] = {
    val xs = mutable.ListBuffer.empty[Commit]
    while (rs.next()) {
      Commit(
        sha = rs.getString("sha"),
        scanned = rs.getBoolean("sha"),
        validated = rs.getBoolean("validated"),
        repositoryId = rs.getInt("repository_id")
      )
    }
    xs.toList
  }

}

object Finding {

  def fromResultSet(rs: ResultSet): List[Finding] = {
    val xs = mutable.ListBuffer.empty[Finding]
    while (rs.next()) {
      Finding(
        id = rs.getInt("id"),
        commitSha = rs.getString("commit_sha"),
        description = rs.getString("description"),
        valid = rs.getBoolean("valid")
      )
    }
    xs.toList
  }

}
