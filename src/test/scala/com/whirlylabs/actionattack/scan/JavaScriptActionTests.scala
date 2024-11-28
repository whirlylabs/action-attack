package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.js.JavaScriptScanner
import io.joern.jssrc2cpg.testfixtures.AstJsSrc2CpgSuite

class JavaScriptActionTests extends AstJsSrc2CpgSuite {
  
  "command injection via `child_process`.exec" in {
    val cpg = code(
      """
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
    JavaScriptScanner(cpg).runScan.size shouldBe 1
  }
  
}