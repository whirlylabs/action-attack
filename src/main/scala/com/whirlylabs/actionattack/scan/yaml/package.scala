package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.Finding
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.nodes.{Node, NodeId, ScalarNode}
import org.yaml.snakeyaml.{LoaderOptions, Yaml}
import ujson.{Arr, Obj}
import upickle.core.*
import upickle.default.*

import scala.jdk.CollectionConverters.*
import scala.util.Try

package object yaml {

  def yamlToJson(yamlStr: String): Try[GitHubActionsWorkflow] = Try {
    val options = LoaderOptions()
    options.setAllowDuplicateKeys(false)
    val yaml = new Yaml(new CustomSafeConstructor(options))
    val data = yaml.load(yamlStr).asInstanceOf[java.util.Map[String, Object]]

    def convertToJson(value: Any): ujson.Value = value match {
      case map: java.util.Map[_, _] =>
        Obj.from(map.asScala.map { case (k, v) =>
          k.toString -> convertToJson(v)
        })
      case list: java.util.List[_] => Arr.from(list.asScala.map(convertToJson))
      case str: String             => ujson.Str(str)
      case num: Number             => ujson.Num(num.doubleValue())
      case bool: java.lang.Boolean => ujson.Bool(bool)
      case null                    => ujson.Null
      case _                       => ujson.Str(value.toString)
    }

    val scalaJson = convertToJson(data)
    val jsonStr   = write(scalaJson)
    read[GitHubActionsWorkflow](jsonStr)
  }

  private class CustomSafeConstructor(options: LoaderOptions) extends SafeConstructor(options) {

    override protected def constructObject(node: Node): Object = {
      if (node.getNodeId == NodeId.scalar && node.isInstanceOf[ScalarNode]) {
        // Check if the key is `on` or `off`, and force it to be treated as a string
        val scalarNode = node.asInstanceOf[ScalarNode]
        scalarNode.getValue match {
          case "on" | "off" => scalarNode.getValue         // Return "on" and "off" as strings
          case _            => super.constructObject(node) // Delegate to SafeConstructor for other cases
        }
      } else {
        super.constructObject(node)
      }
    }
  }

  case class GitHubActionsWorkflow(name: Option[String], on: WorkflowTrigger, jobs: Map[String, Job] = Map.empty)
      derives ReadWriter {
    def runScans(scans: List[YamlScanner]): List[Finding] = {
      scans.flatMap(_.scan(this))
    }
  }

  case class WorkflowTrigger(
    push: Option[Push] = None,
    @upickle.implicits.key("pull_request") pullRequest: Option[PullRequest] = None
  ) derives ReadWriter

  case class Push(branches: Option[List[String]] = None) derives ReadWriter

  case class PullRequest(branches: Option[List[String]] = None) derives ReadWriter

  case class Issues(types: Option[List[String]] = None) derives ReadWriter

  case class Job(@upickle.implicits.key("runs-on") runsOn: String, steps: List[Step]) derives ReadWriter

  case class Step(
    name: Option[String] = None,
    uses: Option[String] = None,
    run: Option[String] = None,
    `with`: Option[Map[String, String]] = None
  ) derives ReadWriter

}
