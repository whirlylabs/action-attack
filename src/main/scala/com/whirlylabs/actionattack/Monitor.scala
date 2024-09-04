package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.Monitor.{CodeSearchItem, CodeSearchResponse, CodeSearchRepository}
import org.slf4j.LoggerFactory
import upickle.core.*
import upickle.default.*

import scala.util.{Failure, Success, Try}

class Monitor(private val db: Database, private val ghToken: String) {

  private val logger = LoggerFactory.getLogger(getClass)

  def start(): Unit = {
    val totalRequestsPerHour     = 5000
    val secondsPerHour           = 3600
    val sleepTimeBetweenRequests = secondsPerHour.toDouble / totalRequestsPerHour.toDouble

    while (true) {
      getRepos match {
        case Success(response) =>
          logger.info(s"Received ${response.items.size} hits")
          response.items.foreach(processHit)
        case Failure(exception) => logger.error("Error while attempting a GitHub code search", exception)
      }
      // Respect GitHub's rate limit of 5000 requests per hour for authenticated requests
      // https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
      Thread.sleep((sleepTimeBetweenRequests * 1000).toLong)
    }
  }

  private def processHit(item: CodeSearchItem): Unit = try {
    val CodeSearchItem(sha, CodeSearchRepository(fullName)) = item
    val List(owner, name)                                   = fullName.split('/').toList: @unchecked
    db.queueCommit(owner, name, sha)
  } catch {
    case e: Exception => logger.error(s"Error occurred while processing $item", e)
  }

  private def getRepos: Try[CodeSearchResponse] = Try {
    val response = requests.get(
      "https://api.github.com/search/code",
      headers = Map(
        "Accept"               -> "application/vnd.github+json",
        "Authorization"        -> s"Bearer $ghToken",
        "X-GitHub-Api-Version" -> "2022-11-28"
      ),
      params = Map("q" -> Monitor.actionsQuery)
    )
    read[CodeSearchResponse](response.text())
  }

}

object Monitor {

  // No regex via search API :( https://github.com/orgs/community/discussions/112338
  //  TODO: add sinks via some other creative way
  private val actionsQuery: String =
    "github.head_ref path:.github/workflows language:YAML"

  case class CodeSearchResponse(
    @upickle.implicits.key("total_count") totalCount: Int,
    @upickle.implicits.key("incomplete_results") incompleteResults: Boolean,
    items: List[CodeSearchItem]
  ) derives ReadWriter

  case class CodeSearchItem(sha: String, repository: CodeSearchRepository) derives ReadWriter

  case class CodeSearchRepository(@upickle.implicits.key("full_name") fullName: String) derives ReadWriter

}
