Feature: Surface read access
  Reading a Surface's configuration needs the Surface view permission.

  Scenario: A management access token without Surface view permission cannot read Surfaces
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    And management access token "metrics-only" for base user "alice" is limited to "metrics.view"
    When management access token "metrics-only" reads LLM Surface "alpha-chat"
    Then the Surface read is forbidden

  Scenario: A management access token with Surface view permission can read Surfaces
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And base user "alice" has published LLM Surface "alpha-chat" for route "/alpha-chat"
    And management access token "surface-reader" for base user "alice" is limited to "pipes.view"
    When management access token "surface-reader" reads LLM Surface "alpha-chat"
    Then the Surface read returns LLM Surface "alpha-chat"
