#!/bin/bash
#
# Script to set up DynamoDB table and populate with example configuration
#

set -e

TABLE_NAME="${1:-agent-stream-configuration}"

echo "Setting up DynamoDB table: $TABLE_NAME"
echo "=========================================="
echo ""

# Create the table
echo "1. Creating DynamoDB table..."
aws dynamodb create-table \
    --table-name "$TABLE_NAME" \
    --attribute-definitions \
        AttributeName=config_type,AttributeType=S \
        AttributeName=config_id,AttributeType=S \
    --key-schema \
        AttributeName=config_type,KeyType=HASH \
        AttributeName=config_id,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --output json > /dev/null 2>&1 || echo "Table may already exist, continuing..."

echo "   Waiting for table to be active..."
aws dynamodb wait table-exists --table-name "$TABLE_NAME"
echo "   ✓ Table created successfully"
echo ""

# Add TLS configuration
echo "2. Adding TLS configuration..."
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "tls"},
        "config_id": {"S": "default"},
        "cert_path": {"S": "cert.pem"},
        "key_path": {"S": "key.pem"},
        "verify_upstream": {"BOOL": true}
    }' > /dev/null
echo "   ✓ TLS configuration added"
echo ""

# Add example channel 1
echo "3. Adding example channels..."
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "channel"},
        "config_id": {"S": "sales-agent"},
        "name": {"S": "sales-agent"},
        "description": {"S": "Channels client requests to the sales agent"},
        "listen_address": {"S": "0.0.0.0:8443"},
        "target_endpoint": {"S": "https://sales-agent.example.com/a2a/v1"}
    }' > /dev/null
echo "   ✓ Added channel: sales-agent (port 8443)"

# Add example channel 2
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "channel"},
        "config_id": {"S": "support-agent"},
        "name": {"S": "support-agent"},
        "description": {"S": "Channels client requests to the customer support agent"},
        "listen_address": {"S": "0.0.0.0:8444"},
        "target_endpoint": {"S": "https://support-agent.example.com/a2a/v1"}
    }' > /dev/null
echo "   ✓ Added channel: support-agent (port 8444)"

# Add example channel 3
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "channel"},
        "config_id": {"S": "analytics-agent"},
        "name": {"S": "analytics-agent"},
        "description": {"S": "Channels client requests to the analytics agent"},
        "listen_address": {"S": "0.0.0.0:8445"},
        "target_endpoint": {"S": "https://analytics-agent.example.com/a2a/v1"}
    }' > /dev/null
echo "   ✓ Added channel: analytics-agent (port 8445)"
echo ""

# Add A2A configuration
echo "4. Adding A2A protocol configuration..."
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "a2a"},
        "config_id": {"S": "default"},
        "default_version": {"S": "0.3"},
        "validate_messages": {"BOOL": true},
        "max_body_size": {"N": "10485760"},
        "timeout_seconds": {"N": "30"}
    }' > /dev/null
echo "   ✓ A2A configuration added"
echo ""

# Add logging configuration
echo "5. Adding logging configuration..."
aws dynamodb put-item \
    --table-name "$TABLE_NAME" \
    --item '{
        "config_type": {"S": "logging"},
        "config_id": {"S": "default"},
        "level": {"S": "info"},
        "json": {"BOOL": false}
    }' > /dev/null
echo "   ✓ Logging configuration added"
echo ""

echo "=========================================="
echo "DynamoDB setup complete!"
echo ""
echo "Table contents:"
aws dynamodb scan --table-name "$TABLE_NAME" --output table
echo ""
echo "Next steps:"
echo "1. Update the target_endpoint values in each channel to point to your actual agents"
echo "2. Ensure cert.pem and key.pem exist (or update the TLS configuration)"
echo "3. Create config.toml with: channel_config_source = \"dynamodb\" and dynamodb_table = \"$TABLE_NAME\""
echo "4. Run the proxy: agent-stream --config config.toml"
