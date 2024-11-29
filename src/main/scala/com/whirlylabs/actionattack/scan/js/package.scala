package com.whirlylabs.actionattack.scan

package object js {
  case class JavaScriptFinding(
    inputKey: String,
    sinkName: String,
    sinkCode: String,
    lineNo: Int,
    sinkDefinesOutput: Boolean
  )
}
