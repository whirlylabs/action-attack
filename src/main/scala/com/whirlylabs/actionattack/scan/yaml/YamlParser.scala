package com.whirlylabs.actionattack.scan.yaml

import org.yaml.snakeyaml.constructor.SafeConstructor
import org.yaml.snakeyaml.nodes.*
import org.yaml.snakeyaml.{LoaderOptions, Yaml}
import ujson.{Arr, Null, Obj, Str}
import upickle.default.*

import java.io.StringReader
import scala.jdk.CollectionConverters.*

object YamlParser {

  def parseToJson(yamlStr: String): ujson.Value = {
    val options = LoaderOptions()
    options.setAllowDuplicateKeys(false)
    val yaml     = new Yaml(new CustomSafeConstructor(options))
    val reader   = new StringReader(yamlStr)
    val rootNode = yaml.compose(reader)
    convertNodeToJsonWithLocation(rootNode)
  }

  private def convertNodeToJsonWithLocation(node: Node): ujson.Value = {
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
        val scalarNode = node.asInstanceOf[ScalarNode]
        scalarNode.getValue match {
          case "on" | "off" => scalarNode.getValue         // Return "on" and "off" as strings
          case _            => super.constructObject(node) // Default behavior for other scalars
        }
      } else {
        super.constructObject(node)
      }
    }

  }

}
