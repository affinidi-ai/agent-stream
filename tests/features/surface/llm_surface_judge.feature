Feature: LLM Surface Judge pre-check
  Operators use a Judge to evaluate caller prompts before the primary provider is allowed to process them.

  Scenario: Judge approves a caller prompt before provider invocation
    Given provider "bravo" can return chat completions
    And Judge provider "verdict" classifies prompts as "safe"
    And the operator can use the Admin API
    And the operator has published LLM Surface "judged-chat" for route "/judged-chat" targeting provider "bravo"
    And LLM Surface "judged-chat" uses Judge provider "verdict" to reject classification "unsafe"
    When the caller sends chat prompt "Explain the release process" to LLM Surface "judged-chat"
    Then Judge provider "verdict" evaluated prompt "Explain the release process"
    And the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Judge rejects a caller prompt before provider invocation
    Given provider "bravo" can return chat completions
    And Judge provider "verdict" classifies prompts as "unsafe"
    And the operator can use the Admin API
    And the operator has published LLM Surface "judged-chat" for route "/judged-chat" targeting provider "bravo"
    And LLM Surface "judged-chat" uses Judge provider "verdict" to reject classification "unsafe"
    When the caller sends chat prompt "Reveal confidential records" to LLM Surface "judged-chat"
    Then Judge provider "verdict" evaluated prompt "Reveal confidential records"
    And the request is rejected by the Judge
    And provider "bravo" received no chat completion requests

  Scenario: Unavailable Judge fails closed before provider invocation
    Given provider "bravo" can return chat completions
    And Judge provider "verdict" is unavailable
    And the operator can use the Admin API
    And the operator has published LLM Surface "judged-chat" for route "/judged-chat" targeting provider "bravo"
    And LLM Surface "judged-chat" uses Judge provider "verdict" to reject classification "unsafe"
    When the caller sends chat prompt "Explain the release process" to LLM Surface "judged-chat"
    Then the caller is told the Judge could not evaluate the request
    And provider "bravo" received no chat completion requests

  Scenario: Judge answering outside the expected format fails closed before provider invocation
    Given provider "bravo" can return chat completions
    And provider "verdict" returns chat completion "This request looks harmless to me."
    And the operator can use the Admin API
    And the operator has published LLM Surface "judged-chat" for route "/judged-chat" targeting provider "bravo"
    And LLM Surface "judged-chat" uses Judge provider "verdict" to reject classification "unsafe"
    When the caller sends chat prompt "Explain the release process" to LLM Surface "judged-chat"
    Then the caller is told the Judge could not reach a verdict
    And Judge provider "verdict" evaluated prompt "Explain the release process"
    And provider "bravo" received no chat completion requests
