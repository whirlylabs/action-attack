package com.whirlylabs.actionattack.scan

import com.whirlylabs.actionattack.{Action, ActionSummary, Finding}
import ujson.{Arr, Obj, Str}
import upickle.core.*
import upickle.default.*

import scala.collection.mutable.ArrayBuffer
import scala.util.Try

package object yaml {

  def yamlToGHWorkflow(yamlStr: String): Try[GitHubActionsWorkflow] = Try {
    val scalaJson = YamlParser.parseToJson(yamlStr)
    read[GitHubActionsWorkflow](scalaJson)
  }

  def runScans(
    actionsFile: GitHubActionsWorkflow,
    scans: List[YamlScanner] = Nil,
    commitSha: String,
    filepath: String,
    actionSummaries: Map[WorkflowAction, List[ActionSummary]]
  ): List[Finding] = {
    scans.flatMap(_.scan(actionsFile, commitSha, filepath, actionSummaries))
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
            val map             = x.obj
            val actionsLocation = read[Location](x("location"))

            val jobs = map.get("jobs")
            jobs.collect { case map: Obj => map.obj.remove("location") }
            val jobMap = jobs.map(read[Map[String, Job]](_)).getOrElse(Map.empty)

            if !map.contains("on") then throw RuntimeException(s"`GitHubActionsWorkflow` expects an `on:` key")
            val onNode = x("on")
            val onLocation = onNode match {
              case on: ujson.Obj => read[Location](on("location"))
              case on: ujson.Arr =>
                val firstElement = on.value.head.arr.head // pretty unsafe, but hey
                read[Location](firstElement.obj("location"))
              case _ => actionsLocation
            }
            val workflowTrigger = onNode match {
              case on: ujson.Obj =>
                val enabledTriggers = on.obj.keySet.flatMap(VulnerableTrigger.fromString).toSet
                WorkflowTrigger(enabledTriggers, onLocation)
              case on: ujson.Arr =>
                val enabledTriggers = on.value.head.arr
                  .map(read[YamlString](_))
                  .flatMap(yamlString => VulnerableTrigger.fromString(yamlString.value))
                  .toSet
                WorkflowTrigger(enabledTriggers, onLocation)
              case _ => WorkflowTrigger(location = onLocation)
            }

            GitHubActionsWorkflow(
              name = if map.contains("name") then Option(read[YamlString](x("name"))) else None,
              on = workflowTrigger,
              jobs = jobMap,
              location = actionsLocation
            )
          case x => throw new RuntimeException(s"`GitHubActionsWorkflow` expects an object, not ${x.getClass}")
        }
      )
    implicit val gitHubActionsTriggerRW: ReadWriter[WorkflowTrigger] = readwriter[ujson.Value].bimap[WorkflowTrigger](
      x => write(x),
      {
        case x: ujson.Obj =>
          val map             = x.obj
          val enabledTriggers = map.keySet.flatMap(VulnerableTrigger.fromString).toSet
          WorkflowTrigger(enabledTriggers, read[Location](x("location")))
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
            val map = x.obj
            val types = map
              .get("types")
              .map {
                case typ: ujson.Obj =>
                  read[YamlString](typ) :: Nil
                case typ: ujson.Arr =>
                  read[List[YamlString]](typ.value.head.arr)
                case _ => Nil
              }
              .getOrElse(Nil)
            Issues(types = types, location = read[Location](x("location")))
          case x => throw new RuntimeException(s"`Push` expects an object, not ${x.getClass}")
        }
      )
    implicit val jobRw: ReadWriter[Job] = readwriter[ujson.Value].bimap[Job](
      x => ujson.Obj("runs-on" -> write(x.runsOn), "steps" -> write(x.steps), "location" -> write(x.location)),
      {
        case x: ujson.Obj =>
          val map      = x.obj
          val stepsOpt = if map.contains("steps") then x("steps").arr else ArrayBuffer.empty
          val steps    = if stepsOpt.isEmpty then Nil else read[List[Step]](stepsOpt.head)
          val runsOn = if map.contains("runs-on") then {
            // `runs-on` is the wild west
            x("runs-on") match {
              case r: ujson.Obj if r.obj.contains("labels") =>
                r.obj("labels") match {
                  case labels: ujson.Str => read[YamlString](labels) :: Nil
                  case labels: ujson.Arr => labels.value.head.arr.map(read[YamlString](_)).toList
                  case _                 => Nil
                }
              case r: ujson.Obj => read[YamlString](r) :: Nil
              case r: ujson.Arr => r.value.head.arr.map(read[YamlString](_)).toList
              case _            => Nil
            }
          } else {
            Nil
          }

          Job(
            name = if map.contains("name") then Option(read[YamlString](x("name"))) else None,
            runsOn = runsOn,
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
          "id"       -> write(x.id),
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
            id = if map.contains("id") then Option(read[YamlString](x("id"))) else None,
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
          val location       = read[Location](x("location"))
          val interpolations = extractGitHubInterpolations(str, location)
          if interpolations.isEmpty then LocatedString(value = str, location = location)
          else InterpolatedString(value = str, location = location, interpolations = interpolations)
        case x =>
          throw new RuntimeException(s"`YamlString` expects an object, not ${x.getClass}")
      }
    )
  }

  private def extractGitHubInterpolations(input: String, baseLocation: Location): Set[LocatedString] = {
    // Regular expression to match the content inside ${{ ... }}
    val interpolationPattern = """\$\{\{\s*([^\}]+)\s*\}\}""".r
    // Find all matches and return the interpolations a set
    input
      .split("\n")
      .zipWithIndex
      .flatMap { case (line, index) =>
        interpolationPattern
          .findAllMatchIn(line)
          .map(matched =>
            LocatedString(
              matched.group(1).trim,
              baseLocation.copy(line = baseLocation.line + index + 2, lineEnd = baseLocation.lineEnd + index + 2)
            )
          )
      }
      .toSet
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

  case class WorkflowTrigger(vulnerableTriggers: Set[VulnerableTrigger] = Set.empty, location: Location)
      extends ActionNode {
    def code: String = vulnerableTriggers.map(t => s"$t: (...)").mkString("\n")
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
    @upickle.implicits.key("runs-on") runsOn: List[YamlString] = Nil,
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
    id: Option[YamlString] = None,
    run: Option[YamlString] = None,
    env: Map[String, YamlString] = Map.empty,
    `with`: Map[String, YamlString] = Map.empty,
    location: Location
  ) extends ActionNode {
    def code: String =
      s"""name: ${name.getOrElse("<unspecified>")}
         |uses: ${uses.getOrElse("<unspecified>")}
         |id: ${id.getOrElse("<unspecified>")}
         |env: ... (${`env`.size}
         |run: ${run.getOrElse("<unspecified>")}
         |with: ... (${`with`.size}
         |""".stripMargin

    /** @return
      *   a list of all values that may be considered sensitive sinks.
      */
    def sinks: List[YamlString] = List(run, `with`.get("cmd"), `with`.get("script")).flatten
  }

  sealed trait YamlString extends ActionNode {

    /** @return
      *   the string literal.
      */
    def value: String
  }

  case class LocatedString(value: String, location: Location) extends YamlString {
    def code: String = value
  }

  case class InterpolatedString(value: String, location: Location, interpolations: Set[LocatedString])
      extends YamlString {
    def code: String = value
  }

  case class Location(line: Int = -1, column: Int = -1, lineEnd: Int = -1, columnEnd: Int = -1) derives ReadWriter

  enum VulnerableTrigger(val name: String) {
    case PullRequest       extends VulnerableTrigger("pull_request")
    case PullRequestTarget extends VulnerableTrigger("pull_request_target")
    case Issues            extends VulnerableTrigger("issues")
    case IssueComment      extends VulnerableTrigger("issue_comment")
    case Discussion        extends VulnerableTrigger("discussion")
    case DiscussionComment extends VulnerableTrigger("discussion_comment")
  }

  object VulnerableTrigger {
    def fromString(input: String): Option[VulnerableTrigger] = VulnerableTrigger.values.find(_.name == input)
  }

}
