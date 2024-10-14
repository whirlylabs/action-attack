package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.scan.yaml.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.{Failure, Success}

class YamlParsingTests extends AnyWordSpec with Matchers {

  "parsing a file with an array `on:` key should pass" in {
    yamlToGHWorkflow("""
        |name: Docs Deployment
        |
        |on: [pull_request]
        |
        |jobs:
        |  deploy:
        |    runs-on: ubuntu-latest
        |    steps:
        |     - name: "Foo"
        |       run: "echo 'hello, world!'"
        |""".stripMargin) match {
      case Failure(exception) => fail(exception)
      case Success(_)         => succeed
    }
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
        |""".stripMargin) match {
      case Failure(exception) => fail(exception)
      case Success(_)         => succeed
    }
  }

  "parsing a file where `runs-on` is an array should pass" in {
    yamlToGHWorkflow("""
        |name: Run E2E Tests
        |on: [pull_request]
        |jobs:
        |  run-e2e:
        |    runs-on: [ubuntu-22.04]
        |    timeout-minutes: 10
        |    strategy:
        |      fail-fast: false
        |    steps:
        |      - uses: actions/checkout@v4
        |""".stripMargin) match {
      case Failure(exception) => fail(exception)
      case Success(_)         => succeed
    }
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
        |""".stripMargin) match {
      case Failure(exception) => fail(exception)
      case Success(_)         => succeed
    }
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
        |""".stripMargin) match {
      case Failure(exception) => fail(exception)
      case Success(_)         => succeed
    }
  }

  "a file with a string containing an unescaped colon should not parse correctly as it is invalid YAML" in {
    yamlToGHWorkflow("""
        |name: Add New Member
        |on:
        |  issues:
        |    types: [opened]
        |
        |jobs:
        |  add_member:
        |    runs-on: ubuntu-latest
        |
        |    steps:
        |      - name: Debugging - Print PR Author
        |        if: env.add_member == 'true'
        |        run: echo "PR Author: ${{ env.pr_author }}"
        |""".stripMargin) match {
      case Failure(_) => succeed
      case Success(_) => fail("This is invalid YAML")
    }
  }

  "GH triggers" should {

    val workflowFile = yamlToGHWorkflow("""
        |name: Multi-Event-Trigger Workflow
        |
        |on:
        |  pull_request:
        |    types: [opened, synchronize, reopened, closed]
        |  pull_request_target:
        |    types: [opened, synchronize, reopened, closed]
        |  issues:
        |    types: [opened, edited, labeled]
        |  issue_comment:
        |    types: [created, edited]
        |  discussion:
        |    types: [created, answered, labeled]
        |  discussion_comment:
        |    types: [created, edited]
        |
        |jobs:
        |  multi-event-job:
        |    runs-on: ubuntu-latest
        |    steps:
        |      - name: Checkout code
        |        uses: actions/checkout@v3
        |
        |      - name: Run for pull_request
        |        if: ${{ github.event_name == 'pull_request' }}
        |        run: echo "Triggered by a pull request event!"
        |
        |      - name: Run for pull_request_target
        |        if: ${{ github.event_name == 'pull_request_target' }}
        |        run: echo "Triggered by a pull request target event!"
        |
        |      - name: Run for pull_request_trigger (custom event)
        |        if: ${{ github.event_name == 'repository_dispatch' && github.event.action == 'pull_request_trigger' }}
        |        run: echo "Triggered by a custom pull_request_trigger event!"
        |
        |""".stripMargin).get

    "parse `pull_request`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.PullRequest)
      workflowFile.on.location.line shouldBe 4
    }

    "parse `pull_request_target`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.PullRequestTarget)
      workflowFile.on.location.line shouldBe 4
    }

    "parse `issues`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.Issues)
      workflowFile.on.location.line shouldBe 4
    }

    "parse `issue_comment`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.IssueComment)
      workflowFile.on.location.line shouldBe 4
    }

    "parse `discussion`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.Discussion)
      workflowFile.on.location.line shouldBe 4
    }

    "parse `discussion_comment`" in {
      workflowFile.on.vulnerableTriggers should contain(VulnerableTrigger.DiscussionComment)
      workflowFile.on.location.line shouldBe 4
    }

  }

}
