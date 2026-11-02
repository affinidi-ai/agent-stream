Feature: LLM Surface Jury response review and redrive
  Operators use a Jury to review provider responses before they are returned to callers and to request a replacement when configured.

  Scenario: Jury approves a provider response
    Given provider "bravo" returns chat completion "Production-ready answer"
    And Jury provider "verdict" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "reviewed-chat" for route "/reviewed-chat" targeting provider "bravo"
    And LLM Surface "reviewed-chat" uses Jury provider "verdict" with no redrives
    When the caller sends a chat completion request to LLM Surface "reviewed-chat"
    Then Jury provider "verdict" reviewed response "Production-ready answer"
    And the caller receives chat completion "Production-ready answer"
    And provider "bravo" received the chat completion request

  Scenario: Jury rejection withholds the provider response
    Given provider "bravo" returns chat completion "Draft answer"
    And Jury provider "verdict" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "reviewed-chat" for route "/reviewed-chat" targeting provider "bravo"
    And LLM Surface "reviewed-chat" uses Jury provider "verdict" with no redrives
    When the caller sends a chat completion request to LLM Surface "reviewed-chat"
    Then Jury provider "verdict" reviewed response "Draft answer"
    And the request is rejected by the Jury
    And provider "bravo" received the chat completion request

  Scenario: Jury redrive replaces a rejected provider response
    Given provider "bravo" returns chat completions "Draft answer" then "Production-ready replacement"
    And Jury provider "verdict" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "reviewed-chat" for route "/reviewed-chat" targeting provider "bravo"
    And LLM Surface "reviewed-chat" uses Jury provider "verdict" with 1 redrive
    When the caller sends a chat completion request to LLM Surface "reviewed-chat"
    Then Jury provider "verdict" reviewed response "Draft answer"
    And Jury provider "verdict" reviewed response "Production-ready replacement"
    And provider "bravo" received 2 chat completion requests
    And the caller receives chat completion "Production-ready replacement"

  Scenario: Jury rejection after all redrives are exhausted
    Given provider "bravo" always returns chat completion "Draft answer"
    And Jury provider "verdict" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "reviewed-chat" for route "/reviewed-chat" targeting provider "bravo"
    And LLM Surface "reviewed-chat" uses Jury provider "verdict" with 2 redrives
    When the caller sends a chat completion request to LLM Surface "reviewed-chat"
    Then provider "bravo" received 3 chat completion requests
    And the request is rejected by the Jury

  Scenario: Unavailable Jury fails closed after provider invocation
    Given provider "bravo" returns chat completion "Production-ready answer"
    And Jury provider "verdict" is unavailable
    And the operator can use the Admin API
    And the operator has published LLM Surface "reviewed-chat" for route "/reviewed-chat" targeting provider "bravo"
    And LLM Surface "reviewed-chat" uses Jury provider "verdict" with no redrives
    When the caller sends a chat completion request to LLM Surface "reviewed-chat"
    Then the caller is told the Jury could not evaluate the response
    And provider "bravo" received the chat completion request
