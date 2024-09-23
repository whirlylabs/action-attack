package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.yaml.CommandInjectionScanner

class CommandInjectionTests extends YamlScanTestFixture(CommandInjectionScanner() :: Nil) {

  "a direct command injection should produce a finding" in {
    val findings = workflow("""
        |name: CI
        |on:
        |  push:
        |    branches:
        |      - main
        |
        |jobs:
        |  setup:
        |    name: Setup and establish latest
        |    runs-on: ubuntu-latest
        |    steps:
        |     - name: 'Test'
        |       run: |
        |         echo "Event name: ${{ github.event_name }}"
        |""".stripMargin)

    inside(findings) { case f1 :: _ =>
      f1.message shouldBe "'setup' has command injection at 'echo \"Event name: ${{ github.event_name }}\"'"
      f1.snippet shouldBe Option("echo \"Event name: ${{ github.event_name }}\"")
      f1.kind shouldBe "command-injection"
      f1.line shouldBe 13
      f1.column shouldBe 12
    }
  }

  "an aliased command injection should produce a finding" in {
    val findings = workflow("""on: issue_comment
        |
        |jobs:
        |  echo-body:
        |    runs-on: ubuntu-latest
        |    steps:
        |     - env:
        |        BODY: ${{ github.event.issue.body }}
        |       run: |
        |        echo '${{ env.BODY }}'
        |""".stripMargin)

    inside(findings) { case f1 :: _ =>
      f1.message shouldBe "'echo-body' has command injection at 'echo '${{ env.BODY }}''"
      f1.snippet shouldBe Option("echo '${{ env.BODY }}'")
      f1.kind shouldBe "command-injection"
      f1.line shouldBe 8
      f1.column shouldBe 12
    }
  }

}
