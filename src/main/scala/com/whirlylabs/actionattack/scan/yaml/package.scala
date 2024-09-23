package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.Finding
import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.nodes.*
import org.yaml.snakeyaml.{LoaderOptions, Yaml}
import ujson.{Arr, Null, Obj, Str}
import upickle.core.*
import upickle.default.*

import java.io.StringReader
import scala.jdk.CollectionConverters.*
import scala.util.Try

package object yaml {

  def yamlToJson(yamlStr: String): Try[GitHubActionsWorkflow] = Try {
    val options = LoaderOptions()
    options.setAllowDuplicateKeys(false)
    val yaml     = new Yaml(new CustomSafeConstructor(options))
    val reader   = new StringReader(yamlStr)
    val rootNode = yaml.compose(reader)

    def convertNodeToJsonWithLocation(node: Node): ujson.Value = {
      node.getNodeId match {
        case NodeId.mapping =>
          val mappingNode = node.asInstanceOf[MappingNode]
          val obj         = ujson.Obj()
          for (tuple <- mappingNode.getValue.asScala) {
            val keyNode   = tuple.getKeyNode.asInstanceOf[ScalarNode]
            val key       = keyNode.getValue
            val valueNode = tuple.getValueNode
            val tupleObj: ujson.Value = convertNodeToJsonWithLocation(valueNode) match {
              case x: Obj => x("location") = valueNode.toLocationObj; x
              case x: Str =>
                ujson.Obj("value" -> x, "location" -> valueNode.toLocationObj)
              case x => x
            }
            obj(key) = tupleObj
          }
          obj("location") = node.toLocationObj
          obj
        case NodeId.sequence =>
          val sequenceNode          = node.asInstanceOf[SequenceNode]
          val childrenWithLocations = sequenceNode.getValue.asScala.map(convertNodeToJsonWithLocation).toSeq
          ujson.Arr(childrenWithLocations)
        case NodeId.scalar =>
          val scalarNode = node.asInstanceOf[ScalarNode]
          scalarNode.getValue
          ujson.Obj("value" -> scalarNode.getValue, "location" -> scalarNode.toLocationObj)
        case _ =>
          ujson.Null
      }
    }

    val scalaJson = convertNodeToJsonWithLocation(rootNode)
    read[GitHubActionsWorkflow](scalaJson)
  }

  implicit class YamlNodeExt(node: Node) {
    def toLocationObj: Obj = ujson.Obj(
      "line"      -> node.getStartMark.getLine,
      "columnEnd" -> node.getEndMark.getLine,
      "column"    -> node.getStartMark.getColumn,
      "columnEnd" -> node.getEndMark.getColumn
    )
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

  def runScans(actionsFile: GitHubActionsWorkflow, scans: List[YamlScanner] = Nil): List[Finding] = {
    scans.flatMap(_.scan(actionsFile))
  }

  sealed trait ActionNode {

    /** @return
      *   the location information of this node in the YAML file.
      */
    def location: Location

    /** @return
      *   a simple code snippet to interpret this node from.
      */
    def code: String
  }

  object ActionNode {

    /** Deserializes the map value at the key of the given map. Makes sure `location` is removed to keep the values a
      * uniform type `YamlString`.
      * @return
      *   the deserialized map.
      */
    private def deserializeMap(
      key: String,
      map: upickle.core.LinkedHashMap[String, ujson.Value]
    ): Map[String, YamlString] = {
      if (map.contains(key)) {
        val envMap = map(key).obj
        envMap.remove("location")
        read[Map[String, YamlString]](envMap)
      } else {
        Map.empty
      }
    }

    // Custom ReadWriters for case classes
    implicit val locationRW: ReadWriter[Location] = macroRW
    implicit val gitHubActionsRW: ReadWriter[GitHubActionsWorkflow] =
      readwriter[ujson.Value].bimap[GitHubActionsWorkflow](
        x => write(x),
        {
          case x: ujson.Obj =>
            val map  = x.obj
            val jobs = map.get("jobs")
            jobs.collect { case map: Obj => map.obj.remove("location") }
            val jobMap = jobs.map(read[Map[String, Job]](_)).getOrElse(Map.empty)
            GitHubActionsWorkflow(
              name = if map.contains("name") then Option(read[YamlString](x("name"))) else None,
              on = read[WorkflowTrigger](x("on")),
              jobs = jobMap,
              location = read[Location](x("location"))
            )
          case x => throw new RuntimeException(s"`GitHubActionsWorkflow` expects an object, not ${x.getClass}")
        }
      )
    implicit val gitHubActionsTriggerRW: ReadWriter[WorkflowTrigger] = readwriter[ujson.Value].bimap[WorkflowTrigger](
      x => write(x),
      {
        case x: ujson.Obj =>
          val map = x.obj
          WorkflowTrigger(
            push = if map.contains("push") then Option(read[Push](x("push"))) else None,
            pullRequest = if map.contains("pull") then Option(read[PullRequest](x("pull"))) else None,
            issues = if map.contains("issues") then Option(read[Issues](x("issues"))) else None,
            location = read[Location](x("location"))
          )
        case x => throw new RuntimeException(s"`Push` expects an object, not ${x.getClass}")
      }
    )
    implicit val pushTriggerRW: ReadWriter[Push] =
      readwriter[ujson.Value].bimap[Push](
        x => write(x),
        {
          case x: ujson.Obj =>
            val map          = x.obj
            val branchesJson = map.get("push")
            branchesJson.collect { case map: Obj => map.obj.remove("location") }
            val branches = branchesJson.map(read[List[YamlString]](_)).getOrElse(Nil)
            Push(branches = branches, location = read[Location](x("location")))
          case x => throw new RuntimeException(s"`Push` expects an object, not ${x.getClass}")
        }
      )
    implicit val pullTriggerRw: ReadWriter[PullRequest] =
      readwriter[ujson.Value].bimap[PullRequest](
        x => write(x),
        {
          case x: ujson.Obj =>
            val map          = x.obj
            val branchesJson = map.get("pull")
            branchesJson.collect { case map: Obj => map.obj.remove("location") }
            val branches = branchesJson.map(read[List[YamlString]](_)).getOrElse(Nil)
            PullRequest(branches = branches, location = read[Location](x("location")))
          case x => throw new RuntimeException(s"`Push` expects an object, not ${x.getClass}")
        }
      )
    implicit val issuesTriggerRw: ReadWriter[Issues] =
      readwriter[ujson.Value].bimap[Issues](
        x => write(x),
        {
          case x: ujson.Obj =>
            val map       = x.obj
            val typesJson = map.get("types")
            typesJson.collect { case map: Obj => map.obj.remove("location") }
            val types = typesJson.map(read[List[YamlString]](_)).getOrElse(Nil)
            Issues(types = types, location = read[Location](x("location")))
          case x => throw new RuntimeException(s"`Push` expects an object, not ${x.getClass}")
        }
      )
    implicit val jobRw: ReadWriter[Job] = readwriter[ujson.Value].bimap[Job](
      x => ujson.Obj("runs-on" -> write(x.runsOn), "steps" -> write(x.steps), "location" -> write(x.location)),
      {
        case x: ujson.Obj =>
          val map      = x.obj
          val stepsOpt = x("steps").arr
          val steps    = if stepsOpt.isEmpty then Nil else read[List[Step]](stepsOpt.head)
          Job(
            name = if map.contains("name") then Option(read[YamlString](x("name"))) else None,
            runsOn = read[YamlString](x("runs-on")),
            steps = steps,
            location = read[Location](x("location"))
          )
        case x => throw new RuntimeException(s"`Job` expects an object, not ${x.getClass}")
      }
    )
    implicit val stepRw: ReadWriter[Step] = readwriter[ujson.Value].bimap[Step](
      x =>
        ujson.Obj(
          "name"     -> write(x.name),
          "uses"     -> write(x.uses),
          "env"      -> write(x.env),
          "run"      -> write(x.run),
          "with"     -> write(x.`with`),
          "location" -> write(x.location)
        ),
      {
        case x: ujson.Obj =>
          val map = x.obj
          Step(
            name = if map.contains("name") then Option(read[YamlString](x("name"))) else None,
            uses = if map.contains("uses") then Option(read[YamlString](x("uses"))) else None,
            run = if map.contains("run") then Option(read[YamlString](x("run"))) else None,
            env = deserializeMap("env", map),
            `with` = deserializeMap("with", map),
            location = read[Location](x("location"))
          )
        case x =>
          throw new RuntimeException(s"`Step` expects an object, not ${x.getClass}")
      }
    )

    implicit val yamlString: ReadWriter[YamlString] = readwriter[ujson.Value].bimap[YamlString](
      {
        case x: LocatedString      => ujson.Obj("value" -> write(x.value), "location" -> write(x.location))
        case x: InterpolatedString => ujson.Obj("value" -> write(x.value), "location" -> write(x.location))
      },
      {
        case x: ujson.Obj =>
          val str            = read[String](x("value"))
          val interpolations = extractGitHubInterpolations(str)
          val location       = read[Location](x("location"))
          if interpolations.isEmpty then LocatedString(value = str, location = location)
          else InterpolatedString(value = str, location = location, interpolations = interpolations)
        case x =>
          throw new RuntimeException(s"`YamlString` expects an object, not ${x.getClass}")
      }
    )
  }

  private def extractGitHubInterpolations(input: String): Set[String] = {
    // Regular expression to match the content inside ${{ ... }}
    val interpolationPattern = """\$\{\{\s*([^\}]+)\s*\}\}""".r
    // Find all matches and return the interpolations a set
    interpolationPattern.findAllMatchIn(input).map(_.group(1).trim).toSet
  }

  case class GitHubActionsWorkflow(
    name: Option[YamlString],
    on: WorkflowTrigger,
    jobs: Map[String, Job] = Map.empty,
    location: Location
  ) extends ActionNode {
    def code: String =
      s"""name: ${name.getOrElse("<unspecified>")}
         |on: ${on.code}
         |jobs: ... (${jobs.size} jobs)
         |""".stripMargin
  }

  case class WorkflowTrigger(
    push: Option[Push] = None,
    @upickle.implicits.key("pull_request") pullRequest: Option[PullRequest] = None,
    issues: Option[Issues] = None,
    location: Location
  ) extends ActionNode {
    def code: String =
      s"""push: ${push.map(_.code).getOrElse("<unspecified>")}
        |pull_request: ${pullRequest.map(_.code).getOrElse("<unspecified>")}
        |issues: ${issues.map(_.code).getOrElse("<unspecified>")}
        |""".stripMargin
  }

  case class Push(branches: List[YamlString] = Nil, location: Location) extends ActionNode {
    def code: String = s"branches: [${branches.mkString(",")}]"
  }

  case class PullRequest(branches: List[YamlString] = Nil, location: Location) extends ActionNode {
    def code: String = s"branches: [${branches.mkString(",")}]"
  }

  case class Issues(types: List[YamlString] = Nil, location: Location) extends ActionNode {
    def code: String = s"types: [${types.mkString(",")}]"
  }

  case class Job(
    name: Option[YamlString] = None,
    @upickle.implicits.key("runs-on") runsOn: YamlString,
    steps: List[Step],
    location: Location
  ) extends ActionNode {
    def code: String = s"""runs-on: $runsOn
                         |steps: ... (${steps.size} steps)
                         |""".stripMargin
  }

  case class Step(
    name: Option[YamlString] = None,
    uses: Option[YamlString] = None,
    run: Option[YamlString] = None,
    env: Map[String, YamlString] = Map.empty,
    `with`: Map[String, YamlString] = Map.empty,
    location: Location
  ) extends ActionNode {
    def code: String =
      s"""name: ${name.getOrElse("<unspecified>")}
         |uses: ${uses.getOrElse("<unspecified>")}
         |env: ... (${`env`.size}
         |run: ${run.getOrElse("<unspecified>")}
         |with: ... (${`with`.size}
         |""".stripMargin

    /** @return
      *   a list of all values that may be considered sensitive sinks.
      */
    def sinks: List[YamlString] = List(run, `with`.get("cmd"), `with`.get("script")).flatten
  }

  sealed trait YamlString {

    /** @return
      *   the string literal.
      */
    def value: String
  }

  case class LocatedString(value: String, location: Location) extends ActionNode with YamlString {
    def code: String = value
  }

  case class InterpolatedString(value: String, location: Location, interpolations: Set[String])
      extends ActionNode
      with YamlString {
    def code: String = value
  }

  case class Location(line: Int = -1, column: Int = -1, lineEnd: Int = -1, columnEnd: Int = -1) derives ReadWriter

}
