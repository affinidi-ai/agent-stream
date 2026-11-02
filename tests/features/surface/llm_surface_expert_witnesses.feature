Feature: LLM Surface Expert Witnesses
  Operators use purpose-trained safety classifiers to inspect caller prompts and provider responses at their configured pipeline seams.

  Scenario: Request Expert Witness allows a caller prompt
    Given provider "bravo" can return chat completions
    And Expert Witness provider "sentinel" allows inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on requests
    When the caller sends chat prompt "Explain the deployment" to LLM Surface "witnessed-chat"
    Then Expert Witness provider "sentinel" inspected content "Explain the deployment"
    And the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Request Expert Witness blocks flagged content before provider invocation
    Given provider "bravo" can return chat completions
    And Expert Witness provider "sentinel" flags inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on requests
    When the caller sends a chat completion request to LLM Surface "witnessed-chat"
    Then the caller is rejected by an Expert Witness
    And provider "bravo" received no chat completion requests

  Scenario: Response Expert Witness allows a provider response
    Given provider "bravo" returns chat completion "Deployment approved"
    And Expert Witness provider "sentinel" allows inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on responses
    When the caller sends a chat completion request to LLM Surface "witnessed-chat"
    Then Expert Witness provider "sentinel" inspected content "Deployment approved"
    And the caller receives chat completion "Deployment approved"

  Scenario: Response Expert Witness withholds flagged provider content
    Given provider "bravo" returns chat completion "Unsafe deployment advice"
    And Expert Witness provider "sentinel" flags inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on responses
    When the caller sends a chat completion request to LLM Surface "witnessed-chat"
    Then provider "bravo" received the chat completion request
    And Expert Witness provider "sentinel" inspected content "Unsafe deployment advice"
    And the caller is rejected by an Expert Witness

  Scenario: Request Expert Witness inspects content after Prompt Guard masking
    Given provider "bravo" can return chat completions
    And Expert Witness provider "sentinel" allows inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Prompt Guard to mask prompts matching "secret-[0-9]+" as "secret"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on requests
    When the caller sends chat prompt "Deploy with secret-42" to LLM Surface "witnessed-chat"
    Then Expert Witness provider "sentinel" inspected content "Deploy with <SECRET>"
    And provider "bravo" received chat prompt "Deploy with <SECRET>"

  Scenario: Response Expert Witness inspects content after Prompt Guard masking
    Given provider "bravo" returns chat completion "Contact ops@example.test"
    And Expert Witness provider "sentinel" allows inspected content
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Prompt Guard to mask responses matching "ops@example[.]test" as "email"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on responses
    When the caller sends a chat completion request to LLM Surface "witnessed-chat"
    Then Expert Witness provider "sentinel" inspected content "Contact <EMAIL>"
    And the caller receives chat completion "Contact <EMAIL>"

  Scenario: Unavailable request Expert Witness fails closed before provider invocation
    Given provider "bravo" can return chat completions
    And Expert Witness provider "sentinel" is unavailable
    And the operator can use the Admin API
    And the operator has published LLM Surface "witnessed-chat" for route "/witnessed-chat" targeting provider "bravo"
    And LLM Surface "witnessed-chat" uses Expert Witness "sentinel" on requests
    When the caller sends a chat completion request to LLM Surface "witnessed-chat"
    Then the caller is told the Expert Witness provider is unavailable
    And provider "bravo" received no chat completion requests
