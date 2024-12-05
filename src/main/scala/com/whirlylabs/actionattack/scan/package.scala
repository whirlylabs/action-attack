package com.whirlylabs.actionattack

package object scan {

  sealed trait ExternalActionsFinding {
    def inputKey: String
    def sinkName: String
    def sinkCode: String
    def lineNo: Int
    def sinkDefinesOutput: Boolean
  }

  case class JavaScriptFinding(
    inputKey: String,
    sinkName: String,
    sinkCode: String,
    lineNo: Int,
    sinkDefinesOutput: Boolean
  ) extends ExternalActionsFinding

}
