package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory

import java.nio.file.Path
import java.sql.{Connection, DriverManager, ResultSet, SQLException}
import scala.collection.mutable
import scala.compiletime.uninitialized
import java.net.{URI, URL}
import scala.util.{Try, Using}
import upickle.default.*

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
    Using.resource(connection.prepareStatement(s"SELECT * FROM commits WHERE scanned = ? LIMIT 1")) { stmt =>
      stmt.setBoolean(1, false)
      Using.resource(stmt.executeQuery())(Commit.fromResultSet(_).headOption)
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

  /** Updates finding validated by user via the TUI
    * @param findingId
    *   id of the finding that needs to be updated
    * @param valid
    *   whether the finding is valid or not (determined by user)
    */
  def updateFinding(findingId: Int, valid: Boolean): Unit = {
    Using.resource(connection.prepareStatement("UPDATE finding SET valid = ?, validatedByUser = ? WHERE id = ?")) {
      stmt =>
        stmt.setBoolean(1, valid)
        stmt.setBoolean(2, true)
        stmt.setInt(3, findingId)
        stmt.execute()
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
    *   all repositories linked to validated and vulnerable commits.
    */
  private def getRepositoriesWithValidatedAndVulnerableCommits: List[Repository] = {
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

  /** @return
    *   all repositories with unvalidated and vulnerable commits.
    */
  private def getRepositoriesWithUnvalidatedAndVulnerableCommits: List[Repository] = {
    Using.resource(
      connection
        .prepareStatement("""SELECT * FROM repository INNER JOIN commits on repository.id = commits.repository_id
          | INNER JOIN finding on finding.commit_sha = commits.sha
          | WHERE finding.validatedByUser = ?
          | AND commits.validated = ?
          |""".stripMargin)
    ) { stmt =>
      stmt.setBoolean(1, false)
      stmt.setBoolean(2, false)
      Using.resource(stmt.executeQuery())(Repository.fromResultSet)
    }
  }

  /** @return
    *   all commits linked to validated and vulnerable findings for the given repository.
    */
  private def getCommitsWithValidatedAndVulnerableFindings(repository: Repository): List[Commit] = {
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

  private def getCommitsWithUnvalidatedAndVulnerableFindings(repository: Repository): List[Commit] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM repository INNER JOIN commits ON repository.id = commits.repository_id INNER JOIN finding ON finding.commit_sha = commits.sha WHERE repository.id = ? AND commits.validated = ? AND finding.validatedByUser = ?"
      )
    ) { stmt =>
      stmt.setInt(1, repository.id)
      stmt.setBoolean(2, false)
      stmt.setBoolean(3, false)
      Using.resource(stmt.executeQuery())(Commit.fromResultSet)
    }
  }

  /** @return
    *   all commits linked to validated and vulnerable findings for the given repository.
    */
  private def getVulnerableFindings(commit: Commit): List[Finding] = {
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

  private def getUnvalidatedFindings(commit: Commit): List[Finding] = {
    Using.resource(
      connection.prepareStatement(
        "SELECT * FROM finding INNER JOIN commits ON finding.commit_sha = commits.sha WHERE finding.validatedByUser = ? AND commits.sha = ?"
      )
    ) { stmt =>
      stmt.setBoolean(1, false)
      stmt.setString(2, commit.sha)
      Using.resource(stmt.executeQuery())(Finding.fromResultSet)
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

  def getUnvalidatedFindingsForReview: Map[Repository, Map[Commit, List[Finding]]] = {
    getRepositoriesWithUnvalidatedAndVulnerableCommits.map { repository =>
      repository -> getCommitsWithUnvalidatedAndVulnerableFindings(repository).map { commit =>
        commit -> getUnvalidatedFindings(commit)
      }.toMap
    }.toMap
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

/** A semi-type safe database definition
  */
object Database {

  implicit class ColExt(name: String) {
    def text: String = s"$name TEXT"

    def int: String = s"$name INTEGER"

    def bool: String = s"$name BOOLEAN"
  }

  private object Columns {
    val Column          = "column".int
    val ColumnEnd       = "column_end".int
    val CommitSha       = "commit_sha".text
    val DefinesOutput   = "defines_output".text
    val FilePath        = "filepath".text
    val Id              = "id".int
    val InputKey        = "input_key".text
    val Kind            = "kind".text
    val Line            = "line".int
    val Message         = "message".text
    val Name            = "name".text
    val Owner           = "owner".text
    val Scanned         = "scanned".bool
    val SinkName        = "sink_name".text
    val Snippet         = "snippet".text
    val Sha             = "sha".text
    val Valid           = "valid".bool
    val Validated       = "validated".bool
    val ValidatedByUser = "validatedByUser".bool
    val Version         = "version".text
  }

  private object TableNames {
    val TRepository     = "repository"
    val TCommits        = "commits"
    val TFinding        = "finding"
    val TPluginVersions = "plugin_versions"
    val TPluginFinding  = "plugin_finding"
  }

  import Columns.*
  import TableNames.*

  private val AUTOINC = "AUTOINCREMENT"
  private val REFS    = "REFERENCES"

  private def CREATE_TABLE(tableName: String, columns: List[String]) =
    s"CREATE TABLE IF NOT EXISTS $tableName (${columns.mkString(",")})"
  private def PK(name: String, autoInc: Boolean = false) = s"$name PRIMARY KEY ${if autoInc then AUTOINC else ""}"
  private def UNIQ(names: String*)                       = s"UNIQUE(${names.mkString(", ")})"
  private def FK(name: String, refTable: String, refCol: String) = s"FOREIGN KEY($name) $REFS $refTable($refCol)"

  private object Tables {
    val RepositoryTable: String =
      CREATE_TABLE(TRepository, PK(Id, true) :: Owner :: Name :: UNIQ("owner", "name") :: Nil)
    val CommitsTable: String =
      CREATE_TABLE(
        TCommits,
        PK(Sha) :: Scanned :: Validated :: "repository_id".int :: FK("repository_id", TRepository, "id") :: Nil
      )
    val FindingsTable: String =
      CREATE_TABLE(
        TFinding,
        PK(Id, true)
          :: CommitSha
          :: Valid
          :: ValidatedByUser
          :: Message
          :: FilePath
          :: Line
          :: Column
          :: ColumnEnd
          :: Snippet
          :: Kind
          :: FK("commit_sha", TCommits, "sha")
          :: Nil
      )
    val PluginVersionsTable: String =
      CREATE_TABLE(
        TPluginVersions,
        PK(Id, true)
          :: Version
          :: Scanned
          :: Validated
          :: "repository_id".int
          :: FK("repository_id", TRepository, "id")
          :: Nil
      )
    val PluginFindingsTable: String =
      CREATE_TABLE(
        TPluginFinding,
        PK(Id, true)
          :: Valid
          :: ValidatedByUser
          :: InputKey
          :: SinkName
          :: Snippet
          :: Line
          :: DefinesOutput
          :: "plugin_id".int
          :: FK("plugin_id", TPluginVersions, "id")
          :: Nil
      )
  }

  import Tables.*

  val schema: List[String] =
    List(RepositoryTable, CommitsTable, FindingsTable, PluginVersionsTable, PluginFindingsTable)

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
  def toUrl: URL = URI(s"https://github.com/$owner/$name.git").toURL

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
  * @param valid
  *   if the finding is valid. This field is only considered if the related commit has been validated.
  * @param validatedByUser
  *   if the finding has been validated by a user or not
  * @param message
  *   the finding description.
  * @param filepath
  *   the relative filepath.
  * @param snippet
  *   a code snippet if available.
  * @param kind
  *   the vulnerability kind.
  */
case class Finding(
  id: Int = -1,
  commitSha: String = "",
  valid: Boolean = false,
  validatedByUser: Boolean = false,
  message: String,
  filepath: String,
  line: Int,
  column: Int,
  @upickle.implicits.key("end_column") columnEnd: Int,
  snippet: Option[String] = None,
  kind: String
) derives ReadWriter

object Repository {

  def fromResultSet(rs: ResultSet): List[Repository] = {
    val xs = mutable.ListBuffer.empty[Repository]
    while (rs.next()) {
      xs.addOne(Repository(id = rs.getInt("id"), owner = rs.getString("owner"), name = rs.getString("name")))
    }
    xs.distinctBy(_.id).toList
  }

}

object Commit {

  def fromResultSet(rs: ResultSet): List[Commit] = {
    val xs = mutable.ListBuffer.empty[Commit]
    while (rs.next()) {
      xs.addOne(
        Commit(
          sha = rs.getString("sha"),
          scanned = rs.getBoolean("sha"),
          validated = rs.getBoolean("validated"),
          repositoryId = rs.getInt("repository_id")
        )
      )
    }
    xs.toList
  }

}

object Finding {

  def fromResultSet(rs: ResultSet): List[Finding] = {
    val xs = mutable.ListBuffer.empty[Finding]
    while (rs.next()) {
      xs.addOne(
        Finding(
          id = rs.getInt("id"),
          commitSha = rs.getString("commit_sha"),
          valid = rs.getBoolean("valid"),
          message = rs.getString("message"),
          filepath = rs.getString("filepath"),
          line = rs.getInt("line"),
          column = rs.getInt("column"),
          columnEnd = rs.getInt("column_end"),
          snippet = Option(rs.getString("snippet")),
          kind = rs.getString("kind")
        )
      )
    }
    xs.toList
  }

}
