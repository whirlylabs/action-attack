package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.queries.{
  ActionQueries,
  ActionSummaryQueries,
  CommitQueries,
  FindingQueries,
  RepositoryQueries
}
import org.slf4j.{Logger, LoggerFactory}
import upickle.default.*

import java.net.{URI, URL}
import java.nio.file.Path
import java.sql.{Connection, DriverManager, ResultSet, SQLException}
import scala.collection.mutable
import scala.compiletime.uninitialized
import scala.util.{Try, Using}

class Database(location: Option[Path] = None)
    extends AutoCloseable
    with FindingQueries
    with CommitQueries
    with RepositoryQueries
    with ActionQueries
    with ActionSummaryQueries {

  protected val logger: Logger = LoggerFactory.getLogger(getClass)

  private val url = location match {
    case Some(path) => s"jdbc:sqlite:$path"
    case None       => "jdbc:sqlite::memory:"
  }
  protected var connection: Connection = uninitialized

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
    val Type            = "type".text
    val Valid           = "valid".bool
    val Validated       = "validated".bool
    val ValidatedByUser = "validated_by_user".bool
    val Version         = "version".text
  }

  private object TableNames {
    val TRepository    = "repository"
    val TCommits       = "commits"
    val TFinding       = "finding"
    val TAction        = "actions"
    val TActionSummary = "action_summary"
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
    val ActionTable: String =
      CREATE_TABLE(
        TAction,
        PK(Id, true)
          :: Version
          :: Scanned
          :: Validated
          :: Type
          :: "repository_id".int
          :: FK("repository_id", TRepository, "id")
          :: UNIQ("version", "repository_id")
          :: Nil
      )
    val ActionSummaryTable: String =
      CREATE_TABLE(
        TActionSummary,
        PK(Id, true)
          :: Valid
          :: ValidatedByUser
          :: InputKey
          :: SinkName
          :: Snippet
          :: Line
          :: DefinesOutput
          :: "action_id".int
          :: FK("action_id", TAction, "id")
          :: Nil
      )
  }

  import Tables.*

  val schema: List[String] =
    List(RepositoryTable, CommitsTable, FindingsTable, ActionTable, ActionSummaryTable)

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
  @upickle.implicits.key("commit_sha") commitSha: String = "",
  valid: Boolean = false,
  @upickle.implicits.key("validated_by_user") validatedByUser: Boolean = false,
  message: String,
  filepath: String,
  line: Int,
  column: Int,
  @upickle.implicits.key("end_column") columnEnd: Int,
  snippet: Option[String] = None,
  kind: String
) derives ReadWriter

case class Action(id: Int, version: String, scanned: Boolean, validated: Boolean, `type`: String, repositoryId: Int)
    derives ReadWriter

case class ActionSummary(
  id: Int,
  valid: Boolean,
  validatedByUser: Boolean,
  inputKey: String,
  sinkName: String,
  snippet: String,
  line: Int,
  definesOutput: Boolean,
  actionId: Int
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
          kind = rs.getString("kind"),
          validatedByUser = rs.getBoolean("validated_by_user")
        )
      )
    }
    xs.toList
  }

}

object Action {
  def fromResultSet(rs: ResultSet): List[Action] = {
    val xs = mutable.ListBuffer.empty[Action]
    while (rs.next()) {
      xs.addOne(
        Action(
          id = Try(rs.getInt("id")).getOrElse(rs.getInt("actions.id")),
          version = rs.getString("version"),
          scanned = rs.getBoolean("scanned"),
          validated = rs.getBoolean("validated"),
          `type` = rs.getString("type"),
          repositoryId = rs.getInt("repository_id")
        )
      )
    }
    xs.toList
  }
}

object ActionSummary {
  def fromResultSet(rs: ResultSet): List[ActionSummary] = {
    val xs = mutable.ListBuffer.empty[ActionSummary]
    while (rs.next()) {
      xs.addOne(
        ActionSummary(
          id = Try(rs.getInt("id")).getOrElse(rs.getInt("action_summary.id")),
          valid = rs.getBoolean("valid"),
          validatedByUser = rs.getBoolean("validated_by_user"),
          inputKey = rs.getString("input_key"),
          sinkName = rs.getString("sink_name"),
          snippet = rs.getString("snippet"),
          line = rs.getInt("line"),
          definesOutput = rs.getBoolean("defines_output"),
          actionId = rs.getInt("action_id")
        )
      )
    }
    xs.toList
  }
}
