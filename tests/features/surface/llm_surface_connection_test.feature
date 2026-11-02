Feature: LLM Surface connection test
  Operators test a saved LLM Surface's provider connection; the test sends the surface's stored provider key only to the endpoint saved with it, so anyone who may run the surface can test it.

  Background:
    Given provider "bravo" can return chat completions
    And the operator has published LLM Surface "keyed-chat" for route "/keyed-chat"
    And LLM Surface "keyed-chat" sends the operator's provider key from secret "operator-key"

  Scenario: An editor without access to secrets tests a surface's provider connection
    Given human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests the provider connection of LLM Surface "keyed-chat"
    Then the connection test succeeds
    And provider "bravo" received the "model list" request

  Scenario: A connection test of a surface without a provider key sends no request
    Given the operator has published LLM Surface "keyless-chat" for route "/keyless-chat"
    And human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests the provider connection of LLM Surface "keyless-chat"
    Then the connection test is refused because the surface has no usable provider key
    And provider "bravo" received no "model list" requests

  Scenario: A connection test whose provider key was deleted sends no request
    Given the operator has deleted secret "operator-key"
    And human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests the provider connection of LLM Surface "keyed-chat"
    Then the connection test is refused because the surface has no usable provider key
    And provider "bravo" received no "model list" requests

  Scenario: An access token that may not run surfaces cannot test a surface's provider connection
    Given human user "admin@example.test" is an administrator using an access token limited to "secrets.view"
    When human user "admin@example.test" tests the provider connection of LLM Surface "keyed-chat"
    Then the connection test is refused
    And provider "bravo" received no "model list" requests

  Scenario: An access token that may run surfaces tests a surface's provider connection
    Given human user "admin@example.test" is an administrator using an access token limited to "pipes.execute"
    When human user "admin@example.test" tests the provider connection of LLM Surface "keyed-chat"
    Then the connection test succeeds
    And provider "bravo" received the "model list" request
