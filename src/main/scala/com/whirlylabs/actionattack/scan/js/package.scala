package com.whirlylabs.actionattack.scan

package object js {
  case class JavaScriptFinding(inputKey: String, sinkCall: String, sinkCode: String, lineNo: Int)
}
