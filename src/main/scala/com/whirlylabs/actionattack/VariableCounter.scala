package com.whirlylabs.actionattack

class VariableCounter {
  private var counter: Int = 0

  def next: Int = {
    counter += 1
    counter
  }

  def currentValue: Int = {
    counter
  }
}
