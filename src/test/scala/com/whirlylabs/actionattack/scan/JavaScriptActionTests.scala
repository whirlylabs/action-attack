package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.js.{JavaScriptFinding, JavaScriptScanner}
import io.joern.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import org.scalatest.Inside

class JavaScriptActionTests extends DataFlowCodeToCpgSuite with Inside {

  "command injection via `child_process`.exec" in {
    val cpg = code("""
        |const core = require('@actions/core');
        |const exec = require('child_process').exec;
        |
        |async function run() {
        |  try {
        |    const userInput = core.getInput('command'); // Input from 'with' in YAML
        |    exec(`echo ${userInput}`, (err, stdout, stderr) => {
        |      if (err) {
        |        core.setFailed(`Command failed: ${err.message}`);
        |      } else {
        |        console.log(`Output: ${stdout}`);
        |      }
        |    });
        |  } catch (error) {
        |    core.setFailed(error.message);
        |  }
        |}
        |
        |run();
        |
        |""".stripMargin)

    inside(JavaScriptScanner(cpg).runScan) { case JavaScriptFinding(inputKey, sinkCall, sinkCode, lineNo) :: Nil =>
      inputKey shouldBe "\"command\""
      sinkCall shouldBe "exec"
      sinkCode should startWith("exec(`echo ${userInput}`")
      lineNo shouldBe 8
    }
  }

}
