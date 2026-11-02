#!/bin/bash

# Install test dependencies for DID:webvh UI components

echo "Installing React Testing Library and related dependencies..."

cd "$(dirname "$0")" || exit 1

npm install --save-dev \
  @testing-library/react@^13.4.0 \
  @testing-library/jest-dom@^5.16.5 \
  @testing-library/user-event@^14.4.3

echo ""
echo "✅ Test dependencies installed successfully!"
echo ""
echo "You can now run tests with:"
echo "  npm test                    # Run tests in watch mode"
echo "  npm test -- --watchAll=false # Run tests once"
echo "  npm test -- --coverage       # Run with coverage report"
echo ""
