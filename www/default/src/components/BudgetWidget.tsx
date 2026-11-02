import React, { useState, useEffect } from 'react';
import { apiClient } from '../api';

interface BudgetUsage {
  pipe_id: string;
  month: string;
  total_spent: number;
  budget_limit: number;
  usage_percentage: number;
  remaining_budget: number;
  alert_threshold_percent: number;
  budget_exceeded: boolean;
  last_updated: string;
}

interface BudgetWidgetProps {
  pipeId: string;
}

const BudgetWidget: React.FC<BudgetWidgetProps> = ({ pipeId }) => {
  const [budget, setBudget] = useState<BudgetUsage | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadBudget();
    const interval = setInterval(loadBudget, 60000); // Refresh every minute
    return () => clearInterval(interval);
  }, [pipeId]);

  const loadBudget = async () => {
    try {
      setLoading(true);
      setError(null);

      const response = await apiClient.fetch(`/api/v1/pipes/${pipeId}/budget`);

      if (!response.ok) {
        throw new Error(`Failed to fetch budget: ${response.status}`);
      }

      const data: BudgetUsage = await response.json();
      setBudget(data);
    } catch (err) {
      console.error('Error loading budget:', err);
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  if (loading && !budget) {
    return <div className="text-gray-500">Loading budget...</div>;
  }

  if (error) {
    return <div className="text-red-500">Error: {error}</div>;
  }

  if (!budget || budget.budget_limit === 0) {
    return <div className="text-gray-500">No budget configured</div>;
  }

  const getStatusColor = () => {
    if (budget.budget_exceeded) return 'text-red-600';
    if (budget.usage_percentage >= budget.alert_threshold_percent) return 'text-orange-600';
    if (budget.usage_percentage >= 50) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getProgressBarColor = () => {
    if (budget.budget_exceeded) return 'bg-red-600';
    if (budget.usage_percentage >= budget.alert_threshold_percent) return 'bg-orange-500';
    if (budget.usage_percentage >= 50) return 'bg-yellow-500';
    return 'bg-green-500';
  };

  const formatCurrency = (amount: number) => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 6,
    }).format(amount);
  };

  return (
    <div className="bg-white rounded-lg shadow p-6 space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-semibold text-gray-900">Monthly Budget</h3>
        <span className="text-sm text-gray-500">{budget.month}</span>
      </div>

      {/* Budget progress bar */}
      <div>
        <div className="flex justify-between text-sm mb-2">
          <span className={`font-medium ${getStatusColor()}`}>
            {budget.usage_percentage.toFixed(1)}% Used
          </span>
          <span className="text-gray-600">
            {formatCurrency(budget.total_spent)} / {formatCurrency(budget.budget_limit)}
          </span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-3 overflow-hidden">
          <div
            className={`h-full transition-all duration-500 ${getProgressBarColor()}`}
            style={{ width: `${Math.min(budget.usage_percentage, 100)}%` }}
          />
        </div>
      </div>

      {/* Budget status */}
      <div className="grid grid-cols-2 gap-4 pt-2">
        <div>
          <div className="text-sm text-gray-500">Remaining</div>
          <div className={`text-lg font-semibold ${getStatusColor()}`}>
            {formatCurrency(budget.remaining_budget)}
          </div>
        </div>
        <div>
          <div className="text-sm text-gray-500">Alert Threshold</div>
          <div className="text-lg font-semibold text-gray-700">
            {budget.alert_threshold_percent}%
          </div>
        </div>
      </div>

      {/* Warnings */}
      {budget.budget_exceeded && (
        <div className="bg-red-50 border border-red-200 rounded-md p-3">
          <div className="flex items-center">
            <svg className="w-5 h-5 text-red-600 me-2" fill="currentColor" viewBox="0 0 20 20">
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
            <span className="text-sm font-medium text-red-800">
              Budget exceeded! Consider disabling this pipe or increasing the budget.
            </span>
          </div>
        </div>
      )}

      {!budget.budget_exceeded && budget.usage_percentage >= budget.alert_threshold_percent && (
        <div className="bg-orange-50 border border-orange-200 rounded-md p-3">
          <div className="flex items-center">
            <svg className="w-5 h-5 text-orange-600 me-2" fill="currentColor" viewBox="0 0 20 20">
              <path
                fillRule="evenodd"
                d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z"
                clipRule="evenodd"
              />
            </svg>
            <span className="text-sm font-medium text-orange-800">
              Approaching budget limit - {formatCurrency(budget.remaining_budget)} remaining
            </span>
          </div>
        </div>
      )}

      {budget.last_updated && (
        <div className="text-xs text-gray-400 pt-2">
          Last updated: {new Date(budget.last_updated).toLocaleString()}
        </div>
      )}
    </div>
  );
};

export default BudgetWidget;
