package com.whirlylabs.actionattack.scan.js

import com.whirlylabs.actionattack.scan.JavaScriptFinding
import io.joern.dataflowengineoss.DefaultSemantics
import io.joern.dataflowengineoss.language.*
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.x2cpg.layers.{Base, CallGraph, ControlFlow, TypeRelations}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.language.*
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.slf4j.LoggerFactory
import io.joern.x2cpg.X2Cpg.stripQuotes

import java.nio.file.Path
import scala.util.{Failure, Success}
import io.joern.dataflowengineoss.language.Path as DataFlowPath
import io.joern.dataflowengineoss.semanticsloader.{
  FlowPath,
  FlowSemantic,
  FullNameSemantics,
  PassThroughMapping,
  Semantics
}

class JavaScriptScanner(input: Either[Path, Cpg]) {

  private val logger = LoggerFactory.getLogger(getClass)
  private val flows = DefaultSemantics.operatorFlows ++ List(
    FlowSemantic(".*@actions/core.*\\.set(Output|Input)", PassThroughMapping :: Nil, regex = true)
  )
  private val semantics                             = FullNameSemantics.fromList(flows)
  private implicit val engineContext: EngineContext = EngineContext(semantics)

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
    val flowsToDangerousSinks = dangerousSinks
      .reachableByFlows(source)
      .passesNot(_.isExpression.inCall.nameExact("stringify")) // A common sanitizer
      .passes(githubInputFetchCall)
      .flatMap(pathToFinding(_, false))
      .toList

    val flowsToOutputSinks = gitHubActionsOutputSinks
      .reachableByFlows(source)
      .passesNot(_.isExpression.inCall.nameExact("stringify"))
      .passes(githubInputFetchCall)
      .flatMap(pathToFinding(_, true))
      .toList

    flowsToDangerousSinks ++ flowsToOutputSinks
  }

  private def pathToFinding(path: DataFlowPath, definesOutput: Boolean): Option[JavaScriptFinding] = {
    path match {
      case DataFlowPath((head: Literal) :: elements) =>
        elements
          .repeat(_._astIn)(
            _.emit.until(
              _.and(
                _.hasLabel(Call.Label),
                _.not(_.propertiesMap.filter(x => Option(x.get("NAME")).exists(_.toString.startsWith("<operator"))))
              )
            )
          )
          .hasLabel(Call.Label)
          .cast[Call]
          .lastOption
          .map { sink =>
            if (definesOutput) {
              JavaScriptFinding(
                stripQuotes(head.code),
                stripQuotes(sink.argument(1).code),
                sink.code,
                sink.lineNumber.get,
                definesOutput
              )
            } else {
              JavaScriptFinding(stripQuotes(head.code), sink.name, sink.code, sink.lineNumber.get, definesOutput)
            }
          }
      case _ => None
    }
  }

  /** Some literal that does not refine an import.
    */
  private def source: Iterator[Expression] = cpg.literal.whereNot(_.inCall.nameExact("require", "import"))

  /** The input from GH actions.
    */
  private def githubInputFetchCall(trav: Iterator[AstNode]) =
    trav.isCall.methodFullName(".*@actions/core.*").nameExact("getInput").argument(1).ast

  /** These sinks are dangerous on their own and, if reached, are exploitable largely on their own.
    */
  private def dangerousSinks: Iterator[Expression] = {
    val fsCalls = cpg.call
      .nameExact("createReadStream", "writeFileSync", "createWriteStream", "open")
      .where(_.receiver.fieldAccess.argument(1).isIdentifier.nameExact("fs"))
      .argument
      .where(_.argumentIndexGte(1))
    val rceCalls =
      (cpg.call.nameExact("exec").methodFullName(".*child\\_process.*") ++ cpg.call.nameExact("eval")).argument(1)
    val requests =
      cpg.call
        .code(".*http.*")
        .where(_.receiver.fieldAccess.argument(1).isIdentifier.nameExact("http", "https"))
        .argument
        .where(_.argumentIndexGte(1))

    fsCalls ++ rceCalls ++ requests
  }

  private def gitHubActionsOutputSinks: Iterator[Expression] = {
    cpg.call.methodFullName(".*@actions/core.*").nameExact("setOutput").argument(2)
  }

}

object JavaScriptScanner {
  def apply(inputDir: Path): JavaScriptScanner = new JavaScriptScanner(Left(inputDir))
  def apply(cpg: Cpg): JavaScriptScanner       = new JavaScriptScanner(Right(cpg))
}
