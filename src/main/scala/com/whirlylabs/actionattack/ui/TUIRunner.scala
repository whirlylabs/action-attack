package com.whirlylabs.actionattack.ui

import com.whirlylabs.actionattack.{Commit, Database, Finding, Repository}
import com.whirlylabs.actionattack.ui.Application.logger
import org.slf4j.LoggerFactory
import tui.crossterm.CrosstermJni
import tui.*

import java.time.{Duration, Instant}
import scala.Ordering.Implicits.*

class TUIRunner {
  private val logger = LoggerFactory.getLogger(getClass)

  def run(db: Database, unvalidatedFindings: Map[Repository, Map[Commit, List[Finding]]], token: String): Unit =
    withTerminal { (jni, terminal) =>
      // create app and run it
      val tick_rate = Duration.ofMillis(250)
      val app       = Application(title = "ActionAttack", enhanced_graphics = true, db, unvalidatedFindings, token)

      run_app(terminal, app, tick_rate, jni)
    }

  def run_app(terminal: Terminal, app: Application, tick_rate: java.time.Duration, jni: CrosstermJni): Unit = {
    var last_tick = Instant.now()

    def elapsed = java.time.Duration.between(last_tick, java.time.Instant.now())

    def timeout = {
      val timeout = tick_rate.minus(elapsed)
      new tui.crossterm.Duration(timeout.toSeconds, timeout.getNano)
    }

    while (true) {
      terminal.draw(f => UI.draw(f, app))

      if (jni.poll(timeout)) {
        jni.read() match {
          case key: tui.crossterm.Event.Key =>
            key.keyEvent.code match {
              case char: tui.crossterm.KeyCode.Char => app.on_key(char.c())
              case _: tui.crossterm.KeyCode.Up      => app.on_up()
              case _: tui.crossterm.KeyCode.Down    => app.on_down()
              case _                                => ()
            }
          case _ => ()
        }
      }
      if (elapsed >= tick_rate) {
        last_tick = Instant.now()
      }
      if (app.should_quit) {
        return
      }
    }
  }
}
