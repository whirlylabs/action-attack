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

  "a file with a `runs-on` map holding a `labels` key should parse successfully" in {
    yamlToGHWorkflow("""
        |name: 'Ephemeral instances'
        |on:
        |  issue_comment:
        |    types: [created]
        |  pull_request:
        |    types: [closed]
        |jobs:
        |  handle-pull-request-event:
        |    needs: config
        |    if: needs.config.outputs.has-secrets &&
        |        ${{ github.event.issue.pull_request && (startsWith(github.event.comment.body, '/deploy-to-hg') || github.event.action == 'closed') }}
        |    runs-on:
        |      labels: ubuntu-latest-8-cores
        |    continue-on-error: true
        |    steps:
        |      - name: Generate a GitHub app installation token
        |        id: generate_token
        |        uses: tibdex/github-app-token@b62528385c34dbc9f38e5f4225ac829252d1ea92
        |        with:
        |          app_id: ${{ secrets.EI_APP_ID }}
        |          private_key: ${{ secrets.EI_APP_PRIVATE_KEY }}
        |
        |      - name: Checkout ephemeral instances repository
        |        uses: actions/checkout@v4
        |        with:
        |          repository: grafana/ephemeral-grafana-instances-github-action
        |          token: ${{ steps.generate_token.outputs.token }}
        |          ref: main
        |          path: ephemeral
        |
        |      - name: build and deploy ephemeral instance
        |        uses: ./ephemeral
        |        with:
        |          github-token:  ${{ steps.generate_token.outputs.token }}
        |          gcom-host: ${{ secrets.EI_GCOM_HOST }}
        |          gcom-token: ${{ secrets.EI_GCOM_TOKEN }}
        |          registry: "${{ secrets.EI_EPHEMERAL_INSTANCES_REGISTRY }}"
        |          gcp-service-account-key: "${{ secrets.EI_GCP_SERVICE_ACCOUNT_KEY_BASE64 }}"
        |          ephemeral-org-id: "${{ secrets.EI_EPHEMERAL_ORG_ID }}"
        |          oss-or-enterprise: oss
        |          verbose: true
        |""".stripMargin).isSuccess shouldBe true
  }

}
