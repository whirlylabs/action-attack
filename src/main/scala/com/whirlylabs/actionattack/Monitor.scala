package com.whirlylabs.actionattack

import com.whirlylabs.actionattack.Monitor.{CodeSearchItem, CodeSearchResponse, CodeSearchRepository}
import org.slf4j.LoggerFactory
import upickle.core.*
import upickle.default.*

import scala.util.{Failure, Success, Try}

class Monitor(private val db: Database, private val ghToken: String) {

  private val logger         = LoggerFactory.getLogger(getClass)
  private val scanner        = Scanner(db)
  private val requestCounter = new VariableCounter;

  sys.addShutdownHook {
    scanner.close()
  }

  def start(): Unit = {
    Thread(scanner).start()
    // Code Search API is 10 requests per minute
    val sleepTimeBetweenRequestsSeconds = 60

    logger.info("Monitoring GitHub for potentially vulnerable repositories...")
    while (true) {
      Monitor.ghActionsSources.foreach { source =>
        Monitor.getRepos(source, ghToken, requestCounter) match {
          case Success(response) =>
            val responseItems = response.flatMap(_.items)
            logger.info(s"Received ${responseItems.size} hits for: $source")

            responseItems.foreach(processHit)
          case Failure(exception) => logger.error("Error while attempting a GitHub code search", exception)
        }

        // Respect GitHub's rate limit of 10 requests per minute for code search
        // https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api?apiVersion=2022-11-28
        if requestCounter.next % 10 == 0 then Thread.sleep((sleepTimeBetweenRequestsSeconds * 1000).toLong)
      }
    }
  }

  private def processHit(item: CodeSearchItem): Unit = try {
    val CodeSearchItem(_, CodeSearchRepository(fullName)) = item
    val commitSha                                         = item.commitHash
    val List(owner, name)                                 = fullName.split('/').toList: @unchecked
    db.queueCommit(owner, name, commitSha)
  } catch {
    case e: Exception => logger.error(s"Error occurred while processing $item", e)
  }

}

object Monitor {
  private val logger                     = LoggerFactory.getLogger(getClass)
  private val resultBuffer: List[String] = List.empty

  /** Generates a code search query. There is <a href="https://github.com/orgs/community/discussions/112338">no regex
    * via search API</a>. :(
    *
    * @param sourceString
    *   the attacker controlled source.
    * @return
    *   a query string.
    */
  private def actionsQuery(sourceString: String): String =
    s"$sourceString path:.github/workflows language:YAML"

  private val ghActionsSources: List[String] = List(
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.pages .page_name",
    "github.event.commits .message",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits .author.email",
    "github.event.commits .author.name",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.head_ref"
  )

  private def getRepos(
    source: String,
    token: String,
    requestCounter: VariableCounter,
    page: Int = 1
  ): Try[List[CodeSearchResponse]] = Try {
    if requestCounter.next % 10 == 0 then Thread.sleep(60 * 1000)

    val response = requests.get(
      "https://api.github.com/search/code",
      headers = Map(
        "Accept"               -> "application/vnd.github+json",
        "Authorization"        -> s"Bearer $token",
        "X-GitHub-Api-Version" -> "2022-11-28"
      ),
      params = Map("q" -> Monitor.actionsQuery(source), "page" -> page.toString, "per_page" -> "100")
    )

    val initialResponse = read[CodeSearchResponse](response.text())
    if initialResponse.incompleteResults then initialResponse :: Nil
    else initialResponse :: paginateRepos(source, token, requestCounter, page + 1)
  }

  private def paginateRepos(
    source: String,
    token: String,
    requestCounter: VariableCounter,
    page: Int
  ): List[CodeSearchResponse] = {
    if requestCounter.next % 10 == 0 then Thread.sleep(60 * 1000)

    val response = requests.get(
      "https://api.github.com/search/code",
      headers = Map(
        "Accept"               -> "application/vnd.github+json",
        "Authorization"        -> s"Bearer $token",
        "X-GitHub-Api-Version" -> "2022-11-28"
      ),
      params = Map("q" -> Monitor.actionsQuery(source), "page" -> page.toString, "per_page" -> "100")
    )

    val responseText = read[CodeSearchResponse](response.text())

    // Can only access 1000 search results, so on page 10 we also need to break out of pagination
    if responseText.incompleteResults || page == 10 then responseText :: Nil
    else responseText :: paginateRepos(source, token, requestCounter, page + 1)
  }

  case class CodeSearchResponse(
    @upickle.implicits.key("total_count") totalCount: Int,
    @upickle.implicits.key("incomplete_results") incompleteResults: Boolean,
    items: List[CodeSearchItem]
  ) derives ReadWriter

  case class CodeSearchItem(url: String, repository: CodeSearchRepository) derives ReadWriter {
    def commitHash: String = url.split('=').last
  }

  case class CodeSearchRepository(@upickle.implicits.key("full_name") fullName: String) derives ReadWriter

}
