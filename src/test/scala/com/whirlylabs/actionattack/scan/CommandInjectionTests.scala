package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.yaml.CommandInjection

class CommandInjectionTests extends YamlScanTestFixture(CommandInjection() :: Nil) {

  "a direct command injection should product a finding" in {
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
      f1.message shouldBe "Job 'setup' contains a command injection"
      f1.snippet shouldBe Option("echo \"Event name: ${{ github.event_name }}\"")
      f1.kind shouldBe "command-injection"
      f1.line shouldBe 13
      f1.column shouldBe 12
    }
  }

}
