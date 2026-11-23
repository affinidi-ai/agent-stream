Feature: Surface run access
  Running a Surface from the Admin API needs the Surface run permission.

  Scenario: A management access token without Surface run permission cannot run a Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    And management access token "metrics-only" for base user "alice" is limited to "metrics.view"
    When management access token "metrics-only" runs LLM Surface "alpha-chat"
    Then the Surface run is forbidden
    And provider "bravo" received no chat completion requests

  Scenario: A management access token with Surface run permission can run a Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    And management access token "surface-runner" for base user "alice" is limited to "pipes.execute"
    When management access token "surface-runner" runs LLM Surface "alpha-chat"
    Then the Surface run returns a chat completion
    And provider "bravo" received the chat completion request
