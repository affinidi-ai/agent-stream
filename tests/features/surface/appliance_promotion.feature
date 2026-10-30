Feature: Promoting a Standby appliance
  A Standby appliance that shares storage with the Active appliance serves, once promoted,
  what the Active appliance stored after the Standby appliance started.

  Background:
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And a Standby appliance shares storage with the Active appliance

  Scenario: A promoted Standby appliance enforces the token cap of a member added on the Active appliance
    Given the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test" with a monthly token cap of 10
    And LLM Surface "governed-chat" enforces member and team usage
    And member "Alice" has consumed 10 tokens through LLM Surface "governed-chat"
    And the Standby appliance has been promoted to replace the Active appliance
    When member "Alice" invokes LLM Surface "governed-chat"
    Then member "Alice" is rejected because the member token cap is exhausted
    And provider "bravo" received 1 chat completion request

  Scenario: A promoted Standby appliance admits a member of a team added on the Active appliance
    Given the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And team "Research" contains member "Alice" without a usage cap
    And LLM Surface "governed-chat" is available only to team "Research"
    And the Standby appliance has been promoted to replace the Active appliance
    When member "Alice" invokes LLM Surface "governed-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received 1 chat completion request

  Scenario: A promoted Standby appliance applies a Surface policy added on the Active appliance
    Given the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And LLM Surface "governed-chat" policy allows caller access tier "gold"
    And the Standby appliance has been promoted to replace the Active appliance
    When the caller sends a chat completion request to LLM Surface "governed-chat" with access tier "gold"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: A user signed in on the Active appliance stays signed in after a Standby appliance is promoted
    Given human user "Dana" may view secrets
    And the Standby appliance has been promoted to replace the Active appliance
    When human user "Dana" requests a protected Admin API resource with their existing session
    Then the request succeeds
