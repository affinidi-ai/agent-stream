Feature: LLM Surface governance records
  Operators can review signed, tamper-evident records of LLM Surface interactions without changing the caller's experience.

  Scenario: Successful interaction produces a signed record with captured bodies
    Given provider "bravo" returns chat completion "Approved answer"
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And governance recording is enabled with body capture for LLM Surface "governed-chat"
    And the caller has completed chat prompt "Explain the policy" through LLM Surface "governed-chat"
    When the operator reviews the latest governance record for LLM Surface "governed-chat"
    Then the governance record request succeeds
    And the latest governance record reports a successful interaction
    And the latest governance record contains prompt "Explain the policy"
    And the latest governance record contains completion "Approved answer"
    And the latest governance record is signed by the appliance
    And provider "bravo" received 1 chat completion request

  Scenario: Successive interactions form a verifiable chain
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And governance recording is enabled with body capture for LLM Surface "governed-chat"
    And the caller has completed chat prompt "First question" through LLM Surface "governed-chat"
    And the caller has completed chat prompt "Second question" through LLM Surface "governed-chat"
    When the operator verifies the governance record chain for LLM Surface "governed-chat"
    Then governance chain verification succeeds
    And the governance record chain contains 2 records
    And provider "bravo" received 2 chat completion requests

  Scenario: Prompt Guard rejection produces a blocked record
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "governed-chat" for route "/governed-chat" targeting provider "bravo"
    And governance recording is enabled with body capture for LLM Surface "governed-chat"
    And LLM Surface "governed-chat" uses Prompt Guard to reject prompts matching "blocked"
    And the caller has been rejected after sending chat prompt "This is blocked" to LLM Surface "governed-chat"
    When the operator reviews the latest governance record for LLM Surface "governed-chat"
    Then the governance record request succeeds
    And the latest governance record reports a Prompt Guard blocked interaction
    And the latest governance record contains blocked prompt "This is blocked"
    And provider "bravo" received no chat completion requests

  Scenario: Body capture can be disabled without losing tamper evidence
    Given provider "bravo" returns chat completion "Private answer"
    And the operator can use the Admin API
    And the operator has published LLM Surface "private-chat" for route "/private-chat" targeting provider "bravo"
    And governance recording is enabled without body capture for LLM Surface "private-chat"
    And the caller has completed chat prompt "Private question" through LLM Surface "private-chat"
    When the operator reviews the latest governance record for LLM Surface "private-chat"
    Then the governance record request succeeds
    And the latest governance record contains a prompt digest
    And the latest governance record contains a completion digest
    And the latest governance record does not retain prompt "Private question"
    And the latest governance record does not retain completion "Private answer"
    And provider "bravo" received 1 chat completion request

  Scenario: Streamed interaction records the reassembled completion
    Given provider "bravo" can stream chat completion "Streamed answer"
    And the operator can use the Admin API
    And the operator has published LLM Surface "streaming-chat" for route "/streaming-chat" targeting provider "bravo"
    And governance recording includes streamed interactions for LLM Surface "streaming-chat"
    And the caller has completed streamed chat prompt "Stream this" through LLM Surface "streaming-chat"
    When the operator reviews the latest governance record for LLM Surface "streaming-chat"
    Then the governance record request succeeds
    And the latest governance record reports a successful interaction
    And the latest governance record contains prompt "Stream this"
    And the latest governance record contains completion "Streamed answer"
    And provider "bravo" received a streaming chat completion request with usage enabled

  Scenario: Recording remains off unless enabled for the LLM Surface
    Given provider "bravo" can return chat completions
    And the operator can use the Admin API
    And the operator has published LLM Surface "ordinary-chat" for route "/ordinary-chat" targeting provider "bravo"
    And the caller has completed a chat interaction through LLM Surface "ordinary-chat"
    When the operator lists LLM Surfaces with governance records
    Then the recorded Surface list request succeeds
    And LLM Surface "ordinary-chat" is absent from the governance record list
    And provider "bravo" received 1 chat completion request
