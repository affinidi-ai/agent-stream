Feature: LLM Surface Decider routing
  Operators use a Decider to select the provider best suited to each caller prompt while preserving a deterministic fallback.

  Scenario Outline: Decider routes a caller prompt to the selected candidate
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And Decider provider "router" selects candidate "<candidate>"
    And the operator can use the Admin API
    And the operator has published LLM Surface "decided-chat" for route "/decided-chat" targeting provider "delta"
    And LLM Surface "decided-chat" uses Decider provider "router" with candidate "fast" targeting provider "bravo" and candidate "smart" targeting provider "charlie"
    When the caller sends chat prompt "<prompt>" to LLM Surface "decided-chat"
    Then Decider provider "router" evaluated prompt "<prompt>"
    And the caller receives a successful chat completion from provider "<provider>"
    And provider "<provider>" received the chat completion request
    And provider "<other-provider>" received no chat completion requests
    And provider "delta" received no chat completion requests

    Examples:
      | prompt                         | candidate | provider | other-provider |
      | Say hello                     | fast      | bravo    | charlie        |
      | Analyze this complex evidence | smart     | charlie  | bravo          |

  Scenario: Unknown Decider selection uses the default candidate
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And Decider provider "router" selects candidate "unknown"
    And the operator can use the Admin API
    And the operator has published LLM Surface "decided-chat" for route "/decided-chat" targeting provider "delta"
    And LLM Surface "decided-chat" uses Decider provider "router" with candidate "fast" targeting provider "bravo" and candidate "smart" targeting provider "charlie"
    And LLM Surface "decided-chat" uses Decider candidate "fast" by default
    When the caller sends chat prompt "Summarize the release notes" to LLM Surface "decided-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request
    And provider "charlie" received no chat completion requests
    And provider "delta" received no chat completion requests

  Scenario: Unavailable Decider fails closed before candidate invocation
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And provider "delta" can return chat completions
    And Decider provider "router" is unavailable
    And the operator can use the Admin API
    And the operator has published LLM Surface "decided-chat" for route "/decided-chat" targeting provider "delta"
    And LLM Surface "decided-chat" uses Decider provider "router" with candidate "fast" targeting provider "bravo" and candidate "smart" targeting provider "charlie"
    When the caller sends a chat completion request to LLM Surface "decided-chat"
    Then the caller is told the Decider could not route the request
    And provider "bravo" received no chat completion requests
    And provider "charlie" received no chat completion requests
    And provider "delta" received no chat completion requests
