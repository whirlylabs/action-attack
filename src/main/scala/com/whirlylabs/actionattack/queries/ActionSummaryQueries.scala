package com.whirlylabs.actionattack.queries

import com.whirlylabs.actionattack.Database
import com.whirlylabs.actionattack.scan.js.JavaScriptFinding

trait ActionSummaryQueries { this: Database =>

  def summarizeAction(actionId: Int, findings: List[JavaScriptFinding]): Unit = {
    this.updateAction(actionId, true)

  }

}
