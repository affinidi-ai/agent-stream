Feature: Encryption at rest choice
  The deployment operator decides whether an appliance encrypts the data it stores. An appliance never stores data unencrypted unless the deployment operator chose that explicitly.

  Scenario: An appliance with no encryption at rest settings does not start
    Given the deployment operator has not configured encryption at rest at all
    When the deployment operator starts the appliance
    Then the appliance does not start
    And the appliance reports that encryption at rest must be enabled or explicitly opted out of

  Scenario: An appliance without an encryption at rest choice does not start
    Given the deployment operator has not chosen whether the appliance encrypts data at rest
    When the deployment operator starts the appliance
    Then the appliance does not start
    And the appliance reports that encryption at rest must be enabled or explicitly opted out of

  Scenario: An appliance with encryption at rest enabled starts and encrypts what it stores
    Given the deployment operator has enabled encryption at rest with a master key
    When the deployment operator starts the appliance
    Then the appliance starts
    And the appliance stores its records encrypted

  Scenario: An appliance whose deployment operator opted out of encryption at rest starts unencrypted
    Given the deployment operator has explicitly opted out of encryption at rest
    When the deployment operator starts the appliance
    Then the appliance starts
    And the appliance stores its records unencrypted
