package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.{Action, ActionSummary, Database}
import com.whirlylabs.actionattack.scan.{ExternalActionsFinding, JavaScriptFinding, WorkflowAction}

import scala.util.Using

trait ActionSummaryQueries { this: Database =>

  def summarizeAction(actionId: Int, findings: List[ExternalActionsFinding]): Unit = {
    findings.groupBy(_.getClass).view.mapValues(_.size).toMap
    val actionType = if (findings.isEmpty) {
      "non-vulnerable" // No need to know how to check if the inputs get sanitised
    } else {
      val (mostCommonActionsType, _) = findings.groupBy(_.getClass).view.mapValues(_.size).toMap.maxBy(_._2)
      mostCommonActionsType match {
        case clazz if clazz == classOf[JavaScriptFinding] => "javascript"
        case _                                            => "unknown"
      }
    }
    this.updateAction(actionId, true, actionType)
    findings.foreach(storeActionSummary(actionId, _))
  }

  private def storeActionSummary(actionId: Int, finding: ExternalActionsFinding): Unit = {
    Using.resource(connection.prepareStatement("""
        |INSERT INTO action_summary(valid, validated_by_user, input_key, sink_name, snippet, line, defines_output, action_id) 
        | VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        |""".stripMargin)) { stmt =>
      stmt.setBoolean(1, false)
      stmt.setBoolean(2, false)
      stmt.setString(3, finding.inputKey)
      stmt.setString(4, finding.sinkName)
      stmt.setString(5, finding.sinkCode)
      stmt.setInt(6, finding.lineNo)
      stmt.setBoolean(7, finding.sinkDefinesOutput)
      stmt.setInt(8, actionId)
      stmt.execute()
    }
  }

  def getSummariesForAction(action: Action): List[ActionSummary] = {
    Using.resource(connection.prepareStatement("""
        |SELECT id, valid, validated_by_user, input_key, sink_name, snippet, line, defines_output, action_id
        |FROM action_summary
        |INNER JOIN actions as a ON a.id = action_summary.action_id
        |WHERE a.id = ?
        |""".stripMargin)) { stmt =>
      stmt.setInt(1, action.id)
      ActionSummary.fromResultSet(stmt.executeQuery())
    }
  }

  def getSummariesForReferencedActions(actions: List[WorkflowAction]): Map[WorkflowAction, List[ActionSummary]] = {
    getActionsFromReferencedActions(actions).map { case (wfa, action) => wfa -> getSummariesForAction(action) }.toMap

  }

}
