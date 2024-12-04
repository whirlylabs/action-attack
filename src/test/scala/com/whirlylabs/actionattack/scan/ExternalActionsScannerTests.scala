package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.yaml.CommandInjectionScanner

class ExternalActionsScannerTests extends YamlScanTestFixture(CommandInjectionScanner() :: Nil) {

  "external actions should be retrievable" in {
    val w = workflow("""
        |on: push
        |
        |jobs:
        |  echo-input:
        |    runs-on: ubuntu-latest
        |    steps:
        |      - uses: actions/github-script@v7
        |        env:
        |          FIRST_NAME: Mona
        |          LAST_NAME: Octocat
        |        with:
        |          script: |
        |            const { FIRST_NAME, LAST_NAME } = process.env
        |
        |            console.log(`Hello ${FIRST_NAME} ${LAST_NAME}`)
        |""".stripMargin)

    inside(ExternalActionsScanner.fetchActionsNames(w :: Nil)) { case action :: Nil =>
      action.owner shouldBe "actions"
      action.name shouldBe "github-script"
      action.version shouldBe "v7"
    }
  }

}
