package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.scan.WorkflowAction
import com.whirlylabs.actionattack.{Action, ActionSummary, Commit, Database, Finding, Repository}

import scala.util.Using

trait ActionQueries { this: Database =>

  /** @return
    *   all actions that have yet to be scanned
    */
  def getUnscannedActions: List[Action] = {
    Using.resource(connection.prepareStatement("SELECT * FROM actions WHERE actions.scanned = ?")) { stmt =>
      stmt.setBoolean(1, false)
      Using.resource(stmt.executeQuery())(Action.fromResultSet)
    }
  }

  /** Adds an action to the database with the intent to be scanned. Will ignore insert if entry already exists.
    *
    * @param owner
    *   the repository owner.
    * @param name
    *   the name of the repository.
    * @param version
    *   the action version.
    */
  def queueAction(owner: String, name: String, version: String): Unit = {
    createRepoIfNotExists(owner, name).foreach { repositoryId =>
      Using.resource(
        connection
          .prepareStatement(
            "INSERT OR IGNORE INTO actions(version, scanned, validated, repository_id) VALUES (?,?,?,?)"
          )
      ) { commitStmt =>
        commitStmt.setString(1, version)
        commitStmt.setBoolean(2, false)
        commitStmt.setBoolean(3, false)
        commitStmt.setInt(4, repositoryId)
        commitStmt.execute()
      }
    }
  }

  def updateAction(id: Int, scanned: Boolean, actionType: String = "unknown"): Unit = {
    Using.resource(connection.prepareStatement("UPDATE actions SET scanned = ?, type = ? WHERE id = ?")) { stmt =>
      stmt.setBoolean(1, scanned)
      stmt.setString(2, actionType)
      stmt.setInt(3, id)
      stmt.execute()
    }
  }
  
  def getActionsFromReferencedActions(actions: List[WorkflowAction]): List[(WorkflowAction, Action)] = {
    actions.flatMap { case w @ WorkflowAction(owner, name, version) =>
      Using.resource(connection.prepareStatement(
        """
          |SELECT id, version, scanned, validated, type, repository_id
          |FROM actions
          |INNER JOIN repository AS r ON r.id = actions.repository_id
          |WHERE actions.version = ? AND r.owner = ? AND r.name = ?
          |""".stripMargin)) { stmt =>
        stmt.setString(1, version)
        stmt.setString(2, owner)
        stmt.setString(3, name)
        Action.fromResultSet(stmt.executeQuery()).headOption.map(x => w -> x)
      }
    }
  }

}
