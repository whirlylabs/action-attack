package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.Database
import com.whirlylabs.actionattack.scan.{ExternalActionsFinding, JavaScriptFinding}

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

  def storeActionSummary(actionId: Int, finding: ExternalActionsFinding): Unit = {
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

}
