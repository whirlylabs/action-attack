package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.yaml.yamlToGHWorkflow
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class YamlParsingTests extends AnyWordSpec with Matchers {

  "parsing a file with an array `on:` key should pass" in {
    yamlToGHWorkflow("""
        |name: Docs Deployment
        |
        |on: [push]
        |
        |jobs:
        |  deploy:
        |    runs-on: ubuntu-latest
        |    steps:
        |     - name: "Foo"
        |       run: "echo 'hello, world!'"
        |""".stripMargin).isSuccess shouldBe true
  }

  "parsing a file with an array on `issue.types` should pass" in {
    yamlToGHWorkflow("""
        |name: Issue Checker
        |
        |on:
        |  issues:
        |    types: [opened, edited, labeled]
        |
        |jobs:
        |  check-permission:
        |    runs-on: ubuntu-latest
        |    outputs:
        |      require-result: ${{ steps.checkUser.outputs.require-result }}
        |    steps:
        |      - uses: actions-cool/check-user-permission@v2
        |        id: checkUser
        |        with:
        |          require: 'write'
        |""".stripMargin).isSuccess shouldBe true
  }

  "parsing a file where `runs-on` is an array should pass" in {
    yamlToGHWorkflow("""
        |name: Run E2E Tests
        |on: [push]
        |jobs:
        |  run-e2e:
        |    runs-on: [ubuntu-22.04]
        |    timeout-minutes: 10
        |    strategy:
        |      fail-fast: false
        |    steps:
        |      - uses: actions/checkout@v4
        |""".stripMargin).isSuccess shouldBe true
  }

  "workflow trigger types as both arrays and strings should pass" in {
    yamlToGHWorkflow("""
        |name: Notify
        |
        |on:
        |  issues:
        |    types:
        |      opened
        |  pull_request_target:
        |    types:
        |      - closed
        |
        |jobs:
        |  notify-issue:
        |    if: ${{ github.event_name == 'issues' }}
        |    runs-on: ubuntu-latest
        |    timeout-minutes: 5
        |    steps:
        |      - uses: snow-actions/nostr@v1.7.0
        |        with:
        |          relays: ${{ vars.NOSTR_RELAYS }}
        |          private-key: ${{ secrets.NOSTR_PRIVATE_KEY }}
        |""".stripMargin).isSuccess shouldBe true
  }

}
