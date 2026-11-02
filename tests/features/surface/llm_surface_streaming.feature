Feature: LLM Surface streaming
  Callers receive OpenAI-compatible Server-Sent Events when passthrough is safe, while configured controls force complete responses through the buffered pipeline.

  Scenario: Eligible request streams provider events to the caller
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    When the caller requests a streamed chat completion from LLM Surface "streaming-chat"
    Then the caller receives an OpenAI-compatible event stream containing "Hello from bravo"
    And the event stream ends with "[DONE]"
    And the streaming response identifies provider "openai"
    And provider "bravo" received a streaming chat completion request with usage enabled

  Scenario: A caller cannot switch off usage on a stream on the operator's provider key
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    When the caller requests a streamed chat completion with usage switched off from LLM Surface "streaming-chat"
    Then the caller receives an OpenAI-compatible event stream containing "Hello from bravo"
    And provider "bravo" received a streaming chat completion request with usage enabled

  Scenario: Unavailable streaming provider returns a typed provider error
    Given provider "bravo" is unavailable for streaming chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    When the caller requests a streamed chat completion from LLM Surface "streaming-chat"
    Then the caller is told the streaming provider is unavailable
    And provider "bravo" received the chat completion request

  Scenario: Request Prompt Guard rejects before opening a provider stream
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And LLM Surface "streaming-chat" uses Prompt Guard to reject prompts matching "blocked"
    When the caller requests streamed chat prompt "This request is blocked" from LLM Surface "streaming-chat"
    Then the request is rejected by the Prompt Guard
    And provider "bravo" received no chat completion requests

  Scenario: Response Prompt Guard forces buffering and masks the complete response
    Given provider "bravo" can stream chat completion "Contact ops@example.test"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And LLM Surface "streaming-chat" uses Prompt Guard to mask responses matching "ops@example[.]test" as "email"
    When the caller requests a streamed chat completion from LLM Surface "streaming-chat"
    Then the caller receives buffered chat completion "Contact <EMAIL>"
    And provider "bravo" received a buffered chat completion request

  Scenario: Operator can disable streaming passthrough
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And the operator has disabled streaming for LLM Surface "streaming-chat"
    When the caller requests a streamed chat completion from LLM Surface "streaming-chat"
    Then the caller receives buffered chat completion "Hello from bravo"
    And provider "bravo" received a buffered chat completion request

  # Streaming used to be excluded from the cache entirely — the SSE passthrough
  # returned before the lookup, so a plain chat surface (the commonest shape
  # there is) never cached anything and the feature read as enabled while doing
  # nothing. This scenario asserted that exclusion; it now asserts the fix.
  #
  # Both halves matter, which is why the provider call count is here: fixing
  # only the lookup looks identical from outside, because it finds nothing a
  # write never stored and every request stays a miss.
  Scenario: A streamed response is stored in the cache and served from it
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And LLM Surface "streaming-chat" uses an exact response cache for 60 seconds
    And the caller has already streamed a chat completion through LLM Surface "streaming-chat"
    When the caller requests streamed chat prompt "Say hello through Agent Stream" from LLM Surface "streaming-chat"
    Then the response reports a cache hit
    And provider "bravo" received 1 chat completion request

  # A hit must still arrive as SSE. The caller asked for an event stream and is
  # parsing frames; handing back a bare JSON object because the answer came from
  # memory would make caching a breaking change for the client.
  Scenario: A cached answer is replayed to a streaming caller as an event stream
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And LLM Surface "streaming-chat" uses an exact response cache for 60 seconds
    And the caller has already streamed a chat completion through LLM Surface "streaming-chat"
    When the caller requests streamed chat prompt "Say hello through Agent Stream" from LLM Surface "streaming-chat"
    Then the caller receives an OpenAI-compatible event stream containing "Hello from bravo"
    And the event stream ends with "[DONE]"

  # Caching is off by default, so a surface that never asked for it must keep
  # calling the provider every time.
  Scenario: A surface without a cache still calls the provider each time
    Given provider "bravo" can stream chat completion "Hello from bravo"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And the caller has already streamed a chat completion through LLM Surface "streaming-chat"
    When the caller requests streamed chat prompt "Say hello through Agent Stream" from LLM Surface "streaming-chat"
    Then the caller receives an OpenAI-compatible event stream containing "Hello from bravo"
    And provider "bravo" received 2 chat completion requests

  Scenario: Streaming provider failure does not invoke a failover provider
    Given provider "bravo" is unavailable for streaming chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And LLM Surface "streaming-chat" fails over to provider "charlie"
    When the caller requests a streamed chat completion from LLM Surface "streaming-chat"
    Then the caller is told the streaming provider is unavailable
    And provider "bravo" received the chat completion request
    And provider "charlie" received no chat completion requests
