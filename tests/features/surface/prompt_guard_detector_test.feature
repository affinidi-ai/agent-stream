Feature: Prompt Guard detector test
  Operators test a model-based PII detector before relying on it; a test sends a stored provider key only to the endpoint saved with it on the surface.

  Background:
    Given provider "bravo" detects person "Alice Example"
    And secret "detector-key" holds a provider key for the whole appliance
    And the operator has published LLM Surface "detected-chat" for route "/detected-chat"
    And LLM Surface "detected-chat" uses a PII detector on provider "bravo" with provider key "detector-key"

  Scenario: An editor tests a PII detector with its saved provider key
    Given human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests the PII detector of LLM Surface "detected-chat"
    Then the detector test finds person "Alice Example"
    And provider "bravo" received provider key "detector-key"

  Scenario: An access token that may not edit surfaces cannot test a PII detector
    Given human user "admin@example.test" is an administrator using an access token limited to "secrets.view"
    When human user "admin@example.test" tests the PII detector of LLM Surface "detected-chat"
    Then the detector test is refused
    And provider "bravo" received no chat completion requests

  Scenario: A detector test does not send a provider key the surface does not use
    Given secret "operator-key" holds a provider key for the whole appliance
    And human user "admin@example.test" may view secrets
    When human user "admin@example.test" tests a PII detector of LLM Surface "detected-chat" on provider "bravo" with provider key "operator-key"
    Then the detector test is refused because the provider key is not saved on the surface
    And provider "bravo" received no chat completion requests

  Scenario: A detector test does not send a saved provider key to another endpoint
    Given provider "charlie" can return chat completions
    And human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests a PII detector of LLM Surface "detected-chat" on provider "charlie" with provider key "detector-key"
    Then the detector test is refused because the provider key is not saved on the surface
    And provider "charlie" received no chat completion requests

  Scenario: A detector test refuses a provider key that does not exist
    Given human user "admin@example.test" may view secrets
    When human user "admin@example.test" tests a PII detector of LLM Surface "detected-chat" on provider "bravo" with provider key "missing-key"
    Then the detector test is refused because the provider key is not saved on the surface
    And provider "bravo" received no chat completion requests

  Scenario: A detector test without a provider key sends none
    Given human user "editor@example.test" edits surfaces without access to secrets
    When human user "editor@example.test" tests a PII detector on provider "bravo" without a provider key
    Then the detector test finds person "Alice Example"
    And provider "bravo" received no provider key

  Scenario: A detector test refuses a private network endpoint
    Given human user "admin@example.test" may view secrets
    When human user "admin@example.test" tests a PII detector at "http://10.0.0.5/v1/chat/completions" without a provider key
    Then the detector test is refused because its endpoint is not allowed
