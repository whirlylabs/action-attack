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
        |         echo "Head ref: ${{ github.head_ref }}"
        |""".stripMargin)

    inside(findings) { case f1 :: _ =>
      f1.message shouldBe "'setup' has command injection at 'echo \"Head ref: ${{ github.head_ref }}\"'"
      f1.snippet shouldBe Option("echo \"Head ref: ${{ github.head_ref }}\"")
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

  "a source that triggers a regex-based match should produce a finding" in {
    val findings = workflow("""on: issue_comment
        |
        |jobs:
        |  echo-body:
        |    runs-on: ubuntu-latest
        |    steps:
        |     - run: |
        |        echo '${{ github.event.pages.blah.page_name }}'
        |""".stripMargin)

    inside(findings) { case f1 :: _ =>
      f1.message shouldBe "'echo-body' has command injection at 'echo '${{ github.event.pages.blah.page_name }}''"
      f1.snippet shouldBe Option("echo '${{ github.event.pages.blah.page_name }}'")
      f1.kind shouldBe "command-injection"
      f1.line shouldBe 6
      f1.column shouldBe 12
    }
  }

}
