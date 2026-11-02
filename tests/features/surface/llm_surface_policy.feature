Feature: LLM Surface policy
  Operators attach policies to LLM Surfaces so permitted caller requests can reach the provider and denied requests stop before provider invocation.

  Scenario: Surface policy allows a caller with a permitted access tier to reach the provider
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    When the caller sends a chat completion request to LLM Surface "policy-chat" with access tier "standard"
    Then the caller receives a successful chat completion from provider "bravo"
    And provider "bravo" received the chat completion request

  Scenario: Surface policy denies a caller with a disallowed access tier before provider invocation
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    When the caller sends a chat completion request to LLM Surface "policy-chat" with access tier "restricted"
    Then the caller is rejected by LLM Surface policy
    And provider "bravo" received no chat completion requests

  Scenario: An unavailable policy definition is rejected before publication
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    When the operator assigns an unavailable policy definition to LLM Surface "policy-chat"
    Then the LLM Surface update is rejected because the policy definition is unavailable
    And provider "bravo" received no chat completion requests

  Scenario: Policy denial does not invoke a failover provider
    Given provider "bravo" can return chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat" targeting provider "bravo"
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    And LLM Surface "policy-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "policy-chat" with access tier "restricted"
    Then the caller is rejected by LLM Surface policy
    And provider "bravo" received no chat completion requests
    And provider "charlie" received no chat completion requests

  Scenario: Surface policy denies a disallowed caller who sends a chat completion request to the discovery path
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat" targeting provider "bravo" as a Custom OpenAI-compatible endpoint
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    When the caller sends a chat completion request to the discovery path of LLM Surface "policy-chat" with access tier "restricted"
    Then the caller is rejected by LLM Surface policy
    And provider "bravo" received no chat completion requests

  Scenario Outline: Surface policy denies a disallowed caller before the provider receives the <operation> request
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    When the caller sends a "<operation>" request to LLM Surface "policy-chat" with access tier "restricted"
    Then the caller is rejected by LLM Surface policy
    And provider "bravo" received no "<operation>" requests

    Examples:
      | operation           |
      | file list           |
      | batch list          |
      | file upload         |
      | audio transcription |
      | audio translation   |

  Scenario Outline: Surface policy lets a permitted caller reach the provider with the <operation> request
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" policy allows caller access tier "standard"
    When the caller sends a "<operation>" request to LLM Surface "policy-chat" with access tier "standard"
    Then the caller receives the "<operation>" response from provider "bravo"
    And provider "bravo" received the "<operation>" request

    Examples:
      | operation           |
      | file list           |
      | batch list          |
      | file upload         |
      | audio transcription |
      | audio translation   |

  Scenario Outline: The appliance-wide LLM policy denies a disallowed caller before the provider receives the <operation> request
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And the appliance-wide LLM policy allows caller access tier "standard"
    When the caller sends a "<operation>" request to LLM Surface "policy-chat" with access tier "restricted"
    Then the caller is rejected by the appliance-wide policy
    And provider "bravo" received no "<operation>" requests

    Examples:
      | operation   |
      | file list   |
      | file upload |

  Scenario Outline: A required verifiable presentation is enforced before the provider receives the <operation> request
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" requires a verifiable presentation from its callers
    When the caller sends a "<operation>" request to LLM Surface "policy-chat"
    Then the caller is rejected because a verifiable presentation is required
    And provider "bravo" received no "<operation>" requests

    Examples:
      | operation   |
      | file list   |
      | file upload |

  Scenario: A caller gets a VP challenge from an LLM Surface that requires a verifiable presentation
    Given the operator can use the Admin API
    And provider "bravo" can return chat completions
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And LLM Surface "policy-chat" requires a verifiable presentation from its callers
    When the caller asks LLM Surface "policy-chat" for a VP challenge
    Then the caller receives a VP challenge for the appliance that expires within 5 minutes
    And provider "bravo" received no chat completion requests

  Scenario: An LLM Surface that does not evaluate verifiable presentations issues no VP challenge
    Given the operator can use the Admin API
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    When the caller asks LLM Surface "policy-chat" for a VP challenge
    Then the caller receives a not found response

  Scenario: Caller without the required API key gets no VP challenge
    Given the operator can use the Admin API
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "policy-chat" requires "API Key" source authentication using secret "caller-api-keys"
    And LLM Surface "policy-chat" requires a verifiable presentation from its callers
    When the caller asks LLM Surface "policy-chat" for a VP challenge without caller credentials
    Then the caller is rejected by source authentication

  Scenario: Caller without the required API key cannot tell whether an LLM Surface issues VP challenges
    Given the operator can use the Admin API
    And the operator has published LLM Surface "policy-chat" for route "/policy-chat"
    And secret "caller-api-keys" contains caller API key "valid-caller-key"
    And LLM Surface "policy-chat" requires "API Key" source authentication using secret "caller-api-keys"
    When the caller asks LLM Surface "policy-chat" for a VP challenge without caller credentials
    Then the caller is rejected by source authentication
