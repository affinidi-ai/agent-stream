Feature: IDE Surface discovery and dispatch
  Operators publish selected LLM Surfaces through one IDE Surface so callers can discover available models and dispatch requests to the chosen provider.

  Scenario: Caller discovers models published by an IDE Surface
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And the operator has published LLM Surface "beta-chat" for route "/ide-beta-chat" targeting provider "charlie"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    And IDE Surface "developer-tools" publishes LLM Surface "beta-chat" as model "beta"
    When the caller discovers models from IDE Surface "developer-tools"
    Then model "alpha" is available to the caller
    And model "beta" is available to the caller

  Scenario Outline: Published IDE models dispatch to their own providers
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And the operator has published LLM Surface "beta-chat" for route "/ide-beta-chat" targeting provider "charlie"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    And IDE Surface "developer-tools" publishes LLM Surface "beta-chat" as model "beta"
    When the caller sends a chat completion request for model "<model>" to IDE Surface "developer-tools"
    Then the caller receives a successful chat completion from provider "<provider>"
    And provider "<provider>" received the chat completion request
    And provider "<other_provider>" received no chat completion requests

    Examples:
      | model | provider | other_provider |
      | alpha | bravo    | charlie        |
      | beta  | charlie  | bravo          |

  Scenario: An IDE dispatch never sends the caller's provider identity token to a provider as a key
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And LLM Surface "alpha-chat" accepts the caller's own provider key
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    When the caller sends a chat completion request for model "alpha" to IDE Surface "developer-tools" with a provider identity token
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" did not receive header "Authorization"

  Scenario: Unknown model cannot be dispatched through an IDE Surface
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    When the caller sends a chat completion request for model "unknown" to IDE Surface "developer-tools"
    Then the caller is told the IDE model was not found
    And provider "bravo" received no chat completion requests

  Scenario: Disabled member LLM Surface is omitted from model discovery
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And the operator has published LLM Surface "beta-chat" for route "/ide-beta-chat" targeting provider "charlie"
    And the operator has disabled LLM Surface "beta-chat"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    And IDE Surface "developer-tools" publishes LLM Surface "beta-chat" as model "beta"
    When the caller discovers models from IDE Surface "developer-tools"
    Then model "alpha" is available to the caller
    And model "beta" is not available to the caller

  Scenario: Disabled member LLM Surface cannot be dispatched through an IDE Surface
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And the operator has published LLM Surface "beta-chat" for route "/ide-beta-chat" targeting provider "charlie"
    And the operator has disabled LLM Surface "beta-chat"
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    And IDE Surface "developer-tools" publishes LLM Surface "beta-chat" as model "beta"
    When the caller sends a chat completion request for model "beta" to IDE Surface "developer-tools"
    Then the caller is told the IDE model is unavailable
    And provider "charlie" received no chat completion requests

  Scenario: Caller gets a VP challenge from an IDE Surface whose model requires a verifiable presentation
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "alpha-chat" for route "/ide-alpha-chat" targeting provider "bravo"
    And LLM Surface "alpha-chat" requires a verifiable presentation from its callers
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    And IDE Surface "developer-tools" publishes LLM Surface "alpha-chat" as model "alpha"
    When the caller asks IDE Surface "developer-tools" for a VP challenge
    Then the caller receives a VP challenge for the appliance that expires within 5 minutes
    And provider "bravo" received no chat completion requests

  Scenario: An IDE Surface refuses VP evidence of its own
    Given the operator can use the Admin API
    And the operator has published IDE Surface "developer-tools" for route "/ide-chat"
    When the operator requires a verifiable presentation from the callers of IDE Surface "developer-tools"
    Then the IDE Surface update is rejected because VP evidence belongs on its member LLM Surfaces
