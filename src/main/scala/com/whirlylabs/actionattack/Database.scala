package com.whirlylabs.actionattack

import org.slf4j.LoggerFactory

import java.nio.file.Path
import java.sql.{Connection, DriverManager, SQLException}
import scala.compiletime.uninitialized
import scala.util.{Try, Using}

class Database(location: Option[Path] = None) extends AutoCloseable {

  // TODO: Create a daemon that runs scans on `commits(scanned=False)`

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
      logger.info("Initializing schema")
      Database.schema.foreach { stmt =>
        statement.execute(stmt)
      }
    }
  } catch {
    case e: SQLException => logger.error("Exception occurred while executing SQL statement", e)
  }

  override def close(): Unit = {
    if (connection != null && !connection.isClosed) {
      println("Closing the database connection...")
      connection.close()
    }
  }

  def queueCommit(owner: String, name: String, commitHash: String): Unit = {
    createRepoIfNotExists(owner, name).foreach { repositoryId =>
      Using.resource(
        connection
          .prepareStatement("INSERT INTO commits(commit_hash, vulnerable, scanned, repository_id) VALUES (?,?,?,?)")
      ) { commitStmt =>
        commitStmt.setString(1, commitHash)
        commitStmt.setBoolean(2, false)
        commitStmt.setBoolean(3, false)
        commitStmt.setInt(4, repositoryId)
        commitStmt.execute()
      }
    }
  }

  private def createRepoIfNotExists(owner: String, name: String): Try[Int] = Try {
    Using.resource(connection.prepareStatement("INSERT OR IGNORE INTO repos(owner, name) VALUES(?, ?)")) { stmt =>
      stmt.setString(1, owner)
      stmt.setString(2, name)
      stmt.execute()
    }

    Using.resource(connection.prepareStatement("SELECT id FROM repos WHERE owner = ? AND name = ?")) { stmt =>
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

  val schema: List[String] = List(
    "CREATE TABLE IF NOT EXISTS repos (id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, name TEXT, UNIQUE(owner, name))",
    "CREATE TABLE IF NOT EXISTS commits (id INTEGER PRIMARY KEY AUTOINCREMENT, commit_hash TEXT, vulnerable BOOLEAN, scanned BOOLEAN, repository_id INTEGER, FOREIGN KEY(repository_id) REFERENCES repos(id))",
    "CREATE TABLE IF NOT EXISTS findings (id INTEGER PRIMARY KEY AUTOINCREMENT, commit_id INTEGER, line TEXT, FOREIGN KEY(commit_id) REFERENCES commits(id))"
  )

}
