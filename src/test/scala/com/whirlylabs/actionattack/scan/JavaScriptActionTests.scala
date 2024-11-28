package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.js.{JavaScriptFinding, JavaScriptScanner}
import io.joern.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import org.scalatest.Inside

class JavaScriptActionTests extends DataFlowCodeToCpgSuite with Inside {

  "Command Injection via child_process.exec" in {
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
      inputKey shouldBe "command"
      sinkCall shouldBe "exec"
      sinkCode should startWith("exec(`echo ${userInput}`")
      lineNo shouldBe 8
    }
  }

  "File Manipulation via fs.writeFileSync" in {
    val cpg = code("""
        |const core = require('@actions/core');
        |const fs = require('fs');
        |
        |async function run() {
        |  try {
        |    const userInput = core.getInput('file-content'); // Input from 'with' in YAML
        |    fs.writeFileSync('output.txt', userInput); // Unsafe write operation
        |    console.log('File written successfully');
        |  } catch (error) {
        |    core.setFailed(`Failed to write file: ${error.message}`);
        |  }
        |}
        |
        |run();
        |
        |""".stripMargin)

    inside(JavaScriptScanner(cpg).runScan) { case JavaScriptFinding(inputKey, sinkCall, sinkCode, lineNo) :: Nil =>
      inputKey shouldBe "file-content"
      sinkCall shouldBe "writeFileSync"
      sinkCode should startWith("fs.writeFileSync('output.txt', userInput)")
      lineNo shouldBe 8
    }
  }

}
