name := "action-attack"
ThisBuild / organization := "com.whirlylabs"
ThisBuild / scalaVersion := "3.4.2"

libraryDependencies ++= Seq(
  "org.jsoup" % "jsoup" % Versions.jsoup,
  "com.github.scopt" %% "scopt" % Versions.scopt,
  "com.lihaoyi" %% "requests" % Versions.requests,
  "com.lihaoyi" %% "upickle" % Versions.upickle,
  "com.lihaoyi" %% "ujson" % Versions.upickle,
  "org.yaml" % "snakeyaml" % Versions.snakeYaml,
  "org.xerial" % "sqlite-jdbc" % Versions.sqlite,
  "org.apache.logging.log4j" % "log4j-slf4j2-impl" % Versions.log4j % Optional,
  "org.scalatest" %% "scalatest" % Versions.scalaTest % Test,
  "com.olvind.tui" %% "tui" % "0.0.7"
)

assembly / assemblyMergeStrategy := {
  case "log4j2.xml" => MergeStrategy.first
  case "module-info.class" => MergeStrategy.first
  case "META-INF/versions/9/module-info.class" => MergeStrategy.first
  case PathList("scala", "collection", "internal", "pprint", _) => MergeStrategy.first
  case x =>
    val oldStrategy = (ThisBuild / assemblyMergeStrategy).value
    oldStrategy(x)
}

ThisBuild / Compile / scalacOptions ++= Seq(
  "-feature",
  "-deprecation",
  "-language:implicitConversions",
)

enablePlugins(JavaAppPackaging)

Global / onChangedBuildSource := ReloadOnSourceChanges

ThisBuild / resolvers ++= Seq(
  Resolver.mavenLocal,
  "Sonatype OSS" at "https://oss.sonatype.org/content/repositories/public",
  "Atlassian" at "https://packages.atlassian.com/mvn/maven-atlassian-external",
  "Gradle Releases" at "https://repo.gradle.org/gradle/libs-releases/"
)

Compile / doc / sources := Seq.empty
Compile / packageDoc / publishArtifact := false
