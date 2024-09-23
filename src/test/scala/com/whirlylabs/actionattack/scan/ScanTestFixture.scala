package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.Finding
import com.whirlylabs.actionattack.scan.yaml.{GitHubActionsWorkflow, YamlScanner, runScans, yamlToJson}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach, Inside}

import scala.util.{Failure, Success}

trait ScanTestFixture extends AnyWordSpec with Matchers with BeforeAndAfterAll with BeforeAndAfterEach with Inside

trait YamlScanTestFixture(scansToRun: List[YamlScanner] = Nil)
    extends ScanTestFixture {

  def workflow(code: String): List[Finding] = {
    yamlToJson(code) match {
      case Failure(exception) => fail("Unable to parse workflow file!", exception)
      case Success(workflow)  => runScans(workflow, scansToRun)
    }
  }

}
