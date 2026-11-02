Feature: LLM Surface telemetry and accounting
  Operators can reconcile caller-visible usage with Surface, pipeline-stage, cache, member, and team accounting.

  Scenario: Completion response reports deterministic token usage and cost
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" prices input and output tokens at 1 dollar per 1000 tokens
    When the caller sends a chat completion request to LLM Surface "accounted-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports 7 input tokens, 3 output tokens, and 10 total tokens
    And the response reports a cost of 0.01 dollars
    And provider "bravo" received 1 chat completion request

  Scenario: Pipeline telemetry attributes usage to the LLM, Judge, and Jury stages
    Given provider "bravo" can return chat completions
    And Judge provider "judge" classifies prompts as "safe"
    And Jury provider "jury" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" uses Judge provider "judge" to reject classification "unsafe"
    And LLM Surface "accounted-chat" uses Jury provider "jury" with no redrives
    When the caller sends a chat completion request to LLM Surface "accounted-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the LLM stage
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the Judge stage
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the Jury stage
    And LLM Surface "accounted-chat" telemetry reports 30 total tokens
    And provider "bravo" received 1 chat completion request
    And provider "judge" received 1 chat completion request
    And provider "jury" received 1 chat completion request

  Scenario: Judge rejection attributes only Judge usage
    Given provider "bravo" can return chat completions
    And Judge provider "judge" classifies prompts as "unsafe"
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" uses Judge provider "judge" to reject classification "unsafe"
    When the caller sends a chat completion request to LLM Surface "accounted-chat"
    Then the request is rejected by the Judge
    And LLM Surface "accounted-chat" telemetry attributes 0 tokens to the LLM stage
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the Judge stage
    And LLM Surface "accounted-chat" telemetry attributes 0 tokens to the Jury stage
    And LLM Surface "accounted-chat" telemetry reports 10 total tokens
    And provider "bravo" received no chat completion requests
    And provider "judge" received 1 chat completion request

  Scenario: Jury rejection attributes LLM and Jury usage
    Given provider "bravo" returns chat completion "Draft answer"
    And Jury provider "jury" rejects responses containing "draft"
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" uses Jury provider "jury" with no redrives
    When the caller sends a chat completion request to LLM Surface "accounted-chat"
    Then the request is rejected by the Jury
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the LLM stage
    And LLM Surface "accounted-chat" telemetry attributes 0 tokens to the Judge stage
    And LLM Surface "accounted-chat" telemetry attributes 10 tokens to the Jury stage
    And LLM Surface "accounted-chat" telemetry reports 20 total tokens
    And provider "bravo" received 1 chat completion request
    And provider "jury" received 1 chat completion request

  Scenario: Prompt Guard rejection records no provider token usage
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" uses Prompt Guard to reject prompts matching "blocked"
    When the caller sends chat prompt "blocked" to LLM Surface "accounted-chat"
    Then the request is rejected by the Prompt Guard
    And LLM Surface "accounted-chat" telemetry reports 0 total tokens
    And provider "bravo" received no chat completion requests

  Scenario: Provider failover accounts only for the recovered completion
    Given provider "bravo" is unavailable for chat completions
    And provider "charlie" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" fails over to provider "charlie"
    When the caller sends a chat completion request to LLM Surface "accounted-chat"
    Then the caller receives a successful chat completion from provider "charlie"
    And LLM Surface "accounted-chat" telemetry reports 10 total tokens
    And provider "bravo" received 1 chat completion request
    And provider "charlie" received 1 chat completion request

  Scenario: Team accounting aggregates each member's Surface usage
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And member "Alice" is identified by header "X-Caller-Email" value "alice@example.test"
    And member "Bob" is identified by header "X-Caller-Email" value "bob@example.test"
    And team "Platform" contains members "Alice" and "Bob" without a usage cap
    And LLM Surface "accounted-chat" enforces member and team usage
    And member "Alice" has invoked LLM Surface "accounted-chat"
    When member "Bob" invokes LLM Surface "accounted-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And team "Platform" accounting reports 20 total tokens
    And member "Alice" accounting reports 10 total tokens for team "Platform"
    And member "Bob" accounting reports 10 total tokens for team "Platform"

  Scenario: Exact cache hit reports avoided provider usage and cost
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "accounted-chat" for route "/accounted-chat" targeting provider "bravo"
    And LLM Surface "accounted-chat" prices input and output tokens at 1 dollar per 1000 tokens
    And LLM Surface "accounted-chat" uses an exact response cache for 60 seconds
    And the caller has cached chat prompt "Repeat me" through LLM Surface "accounted-chat"
    When the caller sends chat prompt "Repeat me" to LLM Surface "accounted-chat"
    Then the caller receives a successful chat completion from provider "bravo"
    And the response reports a cache hit
    And cache accounting reports 1 hit, 10 saved tokens, and 0.01 saved dollars
    And provider "bravo" received 1 chat completion request
