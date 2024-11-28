package com.whirlylabs.actionattack.scan.js

import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.x2cpg.layers.{Base, CallGraph, ControlFlow, TypeRelations}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.language.*
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Literal}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.slf4j.LoggerFactory

import java.nio.file.Path
import scala.util.{Failure, Success}

class JavaScriptScanner(input: Either[Path, Cpg]) {

  private val logger = LoggerFactory.getLogger(getClass)
  private implicit val engineContext: EngineContext = EngineContext()

  private val cpg = input match {
    case Left(inputDir) =>
      JavaScriptParser.createCpg(inputDir) match {
        case Failure(exception) =>
          throw new RuntimeException(s"Unable to successfully create CPG from given input '$inputDir'", exception)
        case Success(cpg) => cpg
      }
    case Right(cpg) => 
      if (!cpg.metaData.overlays.contains("base")) {
        logger.info("Base overlays not detected, applying")
        val context = new LayerCreatorContext(cpg)
        List(new Base(), new ControlFlow(), new TypeRelations(), new CallGraph()).foreach { creator =>
          creator.run(context)
        }
      }
      if (!cpg.metaData.overlays.contains("dataflowOss")) {
        logger.info("Dataflow overlay not detected, applying")
        JavaScriptParser.runPostProcessingOverlays(cpg)
      }
      cpg
  }

  def runScan: List[JavaScriptFinding] = {
    def source = cpg.literal
    def githubInputFetchCall = (trav: Iterator[AstNode]) =>
      trav.isCall.methodFullName(".*@actions/core.*").nameExact("getInput").argument(1).ast
    def sinks = {
      val fsCalls = cpg.call
        .nameExact("createReadStream", "writeFileSync", "createWriteStream", "open")
        .where(_.receiver.fieldAccess.argument(1).isIdentifier.nameExact("fs"))
      val rceCalls = cpg.call.nameExact("exec", "eval")
      val requests =
        cpg.call.code(".*http.*").where(_.receiver.fieldAccess.argument(1).isIdentifier.nameExact("http", "https"))

      (fsCalls ++ rceCalls ++ requests).argument(1)
    }
    sinks
      .reachableByFlows(source)
      .passes(githubInputFetchCall)
      .flatMap {
        case io.joern.dataflowengineoss.language.Path((head: Literal) :: elements) =>
          val sink = elements.isCall.last
          Option(JavaScriptFinding(head.code, sink.name, sink.code, sink.lineNumber.get))
        case _ => None
      }
      .toList
  }

}

object JavaScriptScanner {
  def apply(inputDir: Path): JavaScriptScanner = new JavaScriptScanner(Left(inputDir))
  def apply(cpg: Cpg): JavaScriptScanner       = new JavaScriptScanner(Right(cpg))
}
