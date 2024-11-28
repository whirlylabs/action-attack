package com.whirlylabs.actionattack.scan.js

import io.joern.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.joern.x2cpg.frontendspecific.jssrc2cpg
import io.joern.jssrc2cpg.{JsSrc2Cpg, Config as JsSrcConfig}
import io.joern.x2cpg.passes.frontend.XTypeRecoveryConfig
import io.shiftleft.codepropertygraph.generated.{Cpg, Languages, Operators}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import java.nio.file.Path
import scala.util.Try

object JavaScriptParser {

  def createCpg(inputDir: Path): Try[Cpg] = {
    val config = JsSrcConfig().withInputPath(inputDir.toString)
    JsSrc2Cpg().createCpgWithOverlays(config).map(runPostProcessingOverlays)
  }

  def runPostProcessingOverlays(cpg: Cpg): Cpg = {
    new OssDataFlow(new OssDataFlowOptions()).run(new LayerCreatorContext(cpg))
    jssrc2cpg.postProcessingPasses(cpg, XTypeRecoveryConfig()).foreach(_.createAndApply())
    cpg
  }

}
