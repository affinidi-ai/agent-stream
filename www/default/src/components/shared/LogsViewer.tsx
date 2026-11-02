import React, { useState, useRef, useEffect, useMemo } from 'react';
import { useApp } from '../../context/AppContext';
import { LogEntry } from '../../types';
import { escapeHtml } from '../../utils/escapeHtml';
import { formatLogTimestamp } from '../../utils/stringUtils';
import { UI_COLORS } from '../../utils/uiPalette';
import { AppButton } from './AppButton';
import './LogsViewer.css';

interface LogsViewerProps {
  filterPrefix?: string;
  title: string;
  subtitle?: string;
  stripAllPrefixes?: boolean; // If true, strip all [CHANNEL:*] and [PIPE:*] prefixes
  height?: string; // Custom height for the log content area
  headerActions?: React.ReactNode; // Extra buttons rendered to the left of Pause
}

const LogsViewer: React.FC<LogsViewerProps> = ({
  filterPrefix,
  title,
  subtitle,
  stripAllPrefixes = false,
  height,
  headerActions,
}) => {
  const { state, actions, getCurrentStats } = useApp();
  const [isPaused, setIsPaused] = useState(false);
  const [isAutoScroll, setIsAutoScroll] = useState(true);
  const [displayedLogs, setDisplayedLogs] = useState<LogEntry[]>([]);
  const [pendingLogs, setPendingLogs] = useState<LogEntry[]>([]);
  const [forceRefresh, setForceRefresh] = useState(false);
  const logContentRef = useRef<HTMLPreElement>(null);
  const lastLogLinesRef = useRef<LogEntry[]>([]);
  // When > 0, only show logs with file_position above this watermark (set on Clear)
  const [clearWatermark, setClearWatermark] = useState(0);

  // Get log timestamp format from settings (default to 'local')
  const logTimestampFormat = state.settings?.log_timestamp_format || 'local';

  // Get all log entries from current stats (filtered view)
  const stats = getCurrentStats();
  const allLogEntries = useMemo(
    () => stats?.proxy_info?.log_entries || [],
    [stats?.proxy_info?.log_entries]
  );

  // Filter logs by the provided prefix - keep as LogEntry objects
  const logEntries = useMemo(() => {
    if (!allLogEntries || allLogEntries.length === 0) {
      return [];
    }

    // If no filter prefix is provided, return all logs
    if (!filterPrefix) {
      return allLogEntries;
    }

    // Filter logs that have the specified prefix in the message
    return allLogEntries.filter((entry: LogEntry) => entry.message.includes(filterPrefix));
  }, [allLogEntries, filterPrefix]);

  // Apply clear watermark: only show logs written after the clear point
  const visibleLogEntries = useMemo(() => {
    if (clearWatermark > 0) {
      return logEntries.filter(e => e.file_position > clearWatermark);
    }
    return logEntries;
  }, [logEntries, clearWatermark]);

  // Initialize displayed logs on first load
  useEffect(() => {
    if (displayedLogs.length === 0 && visibleLogEntries.length > 0) {
      setDisplayedLogs(visibleLogEntries);
      lastLogLinesRef.current = visibleLogEntries;
    }
  }, [visibleLogEntries, displayedLogs.length]);

  // Handle log updates - store new logs in pending if paused, otherwise display immediately
  useEffect(() => {
    // Skip update if visible entries haven't actually changed (deep equality check)
    if (
      lastLogLinesRef.current.length === visibleLogEntries.length &&
      lastLogLinesRef.current.every(
        (entry, index) => entry.file_position === visibleLogEntries[index].file_position
      )
    ) {
      return;
    }

    lastLogLinesRef.current = visibleLogEntries;

    if (isPaused && !forceRefresh) {
      // When paused, don't update displayed logs but store the latest logs as pending
      setPendingLogs(visibleLogEntries);
    } else {
      // When not paused, or when forcing refresh, update displayed logs and clear any pending logs
      setDisplayedLogs(visibleLogEntries);
      setPendingLogs([]);
      if (forceRefresh) {
        setForceRefresh(false);
      }
    }
  }, [visibleLogEntries, isPaused, forceRefresh]);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (isAutoScroll && logContentRef.current && !isPaused) {
      logContentRef.current.scrollTop = logContentRef.current.scrollHeight;
    }
  }, [displayedLogs, isAutoScroll, isPaused]);

  const togglePause = () => {
    if (isPaused) {
      // When resuming, show all pending logs
      setDisplayedLogs(pendingLogs.length > 0 ? pendingLogs : visibleLogEntries);
      setPendingLogs([]);
    }
    setIsPaused(!isPaused);
  };

  const refreshLogs = () => {
    // Set force refresh to true so that even if paused, we show the latest logs
    // Also reset the clear watermark so all logs are visible again
    setClearWatermark(0);
    setForceRefresh(true);
    actions.loadDashboardStats(true);
  };

  // Get color for log level
  const getLevelColor = (level: string): string => {
    switch (level.toUpperCase()) {
      case 'ERROR':
        return UI_COLORS.danger;
      case 'WARN':
        return UI_COLORS.warning;
      case 'INFO':
        return UI_COLORS.primary;
      case 'DEBUG':
        return UI_COLORS.success;
      case 'TRACE':
        return UI_COLORS.neutralMuted;
      default:
        return UI_COLORS.neutral;
    }
  };

  // Convert ANSI color codes to HTML spans with colors
  const ansiToHtml = (text: string): string => {
    // ANSI color code mapping to CSS colors
    const ansiColors: Record<string, string> = {
      // Foreground colors (vivid for dark terminal background)
      '30': '#000000', // black
      '31': '#ff5555', // red
      '32': '#50fa7b', // green
      '33': '#f1fa8c', // yellow
      '34': '#6272a4', // blue
      '35': '#ff79c6', // magenta
      '36': '#8be9fd', // cyan
      '37': '#f8f8f2', // white

      // Bright colors
      '90': '#6272a4', // bright black (gray)
      '91': '#ff6e6e', // bright red
      '92': '#69ff94', // bright green
      '93': '#ffffa5', // bright yellow
      '94': '#d6acff', // bright blue
      '95': '#ff92df', // bright magenta
      '96': '#a4ffff', // bright cyan
      '97': '#ffffff', // bright white
    };

    // Default color for logs
    let currentColor = '#00ff00';
    let currentStyle = '';
    let result = '';

    // Split by ANSI escape sequences
    const escapeChar = '\u001b';
    const ansiRegex = new RegExp(`(${escapeChar}\\[[0-9;]*m)`, 'g');
    const parts = text.split(ansiRegex);

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];

      // Check if this is an ANSI escape sequence
      const ansiMatchRegex = new RegExp(`${escapeChar}\\[([0-9;]*)m`);
      const ansiMatch = part.match(ansiMatchRegex);

      if (ansiMatch) {
        // Parse the codes
        const codes = ansiMatch[1].split(';').filter(c => c !== '');

        for (const code of codes) {
          if (code === '0' || code === '') {
            // Reset all attributes
            currentColor = '#00ff00';
            currentStyle = '';
          } else if (code === '1') {
            // Bold
            currentStyle = 'font-weight: bold;';
          } else if (code === '2') {
            // Dim/faint - make slightly transparent
            currentStyle = 'opacity: 0.6;';
          } else if (code === '22') {
            // Normal intensity
            currentStyle = '';
          } else if (ansiColors[code]) {
            // Color code
            currentColor = ansiColors[code];
          }
        }
      } else if (part) {
        // Regular text - wrap in span with current color
        const escapedText = escapeHtml(part);
        if (currentStyle) {
          result += `<span style="color: ${currentColor}; ${currentStyle}">${escapedText}</span>`;
        } else {
          result += `<span style="color: ${currentColor};">${escapedText}</span>`;
        }
      }
    }

    return result || `<span style="color: #00ff00;">${escapeHtml(text)}</span>`;
  };

  const formatLogContent = () => {
    if (displayedLogs.length === 0) {
      return `<span style="color: ${UI_COLORS.neutralMuted};">No logs available${subtitle ? ` for ${escapeHtml(subtitle)}` : ''}</span>`;
    }

    // Deduplicate consecutive identical log entries
    const deduplicatedLogs: LogEntry[] = [];
    let lastEntry: LogEntry | null = null;

    for (const entry of displayedLogs) {
      if (!lastEntry || entry.file_position !== lastEntry.file_position) {
        deduplicatedLogs.push(entry);
        lastEntry = entry;
      }
    }

    // Strip filter prefix from logs since we already know the context
    // Or strip all common prefixes if stripAllPrefixes is true
    // Convert log entries to HTML with proper formatting
    return deduplicatedLogs
      .map((entry: LogEntry) => {
        const timestamp = formatLogTimestamp(entry.timestamp, logTimestampFormat);
        const levelColor = getLevelColor(entry.level);

        // Remove the filter prefix or all common prefixes from the message
        let cleanedMessage = entry.message;

        if (stripAllPrefixes) {
          // Strip all [CHANNEL:*] and [PIPE:*] prefixes
          cleanedMessage = cleanedMessage
            .replace(/\[CHANNEL:[^\]]+\]\s*/g, '')
            .replace(/\[PIPE:[^\]]+\]\s*/g, '')
            .trim();
        } else if (filterPrefix && entry.message.includes(filterPrefix)) {
          // Remove only the specific filter prefix
          cleanedMessage = entry.message.replace(filterPrefix, '').trim();
        }

        // Convert ANSI codes in the message to HTML
        const coloredMessage = ansiToHtml(cleanedMessage);

        return `<span style="color: ${UI_COLORS.neutralMuted}">${escapeHtml(timestamp)}</span> <span style="color: ${levelColor}; font-weight: bold">${escapeHtml(entry.level)}</span> ${coloredMessage}`;
      })
      .join('\n');
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-file-alt"></i> {title} {subtitle && `- ${subtitle}`}
        </h6>
        <div className="d-flex align-items-center gap-2 logs-controls">
          {headerActions}
          <AppButton
            variant="outline-danger"
            size="sm"
            onClick={() => {
              // Record the highest file_position as watermark; only logs after this will be shown
              const maxPos = logEntries.reduce((max, e) => Math.max(max, e.file_position), 0);
              setClearWatermark(maxPos);
              setDisplayedLogs([]);
              setPendingLogs([]);
              lastLogLinesRef.current = [];
            }}
            title="Clear displayed logs"
            iconStart={<i className="fas fa-trash-alt me-1" aria-hidden="true" />}
          >
            Clear
          </AppButton>
          <AppButton
            variant="outline-secondary"
            size="sm"
            onClick={togglePause}
            title={
              isPaused && pendingLogs.length > displayedLogs.length
                ? `${pendingLogs.length - displayedLogs.length} new logs available`
                : undefined
            }
            iconStart={
              <i className={`fas fa-${isPaused ? 'play' : 'pause'} me-1`} aria-hidden="true" />
            }
          >
            {isPaused
              ? pendingLogs.length > displayedLogs.length
                ? `Resume (${pendingLogs.length - displayedLogs.length} new)`
                : 'Resume'
              : 'Pause'}
          </AppButton>
          <AppButton
            variant="primary"
            size="sm"
            onClick={refreshLogs}
            iconStart={<i className="fas fa-sync-alt me-1" aria-hidden="true" />}
          >
            Refresh
          </AppButton>
          <small className="text-muted">
            {displayedLogs.length} log{displayedLogs.length !== 1 ? 's' : ''}
          </small>
        </div>
      </div>
      <div className="card-body p-0">
        <pre
          ref={logContentRef}
          className="log-viewer"
          style={{
            height: height || 'calc(100vh - 250px)',
            minHeight: height ? undefined : '400px',
          }}
          dangerouslySetInnerHTML={{ __html: formatLogContent() }}
        />
      </div>
    </div>
  );
};

export default LogsViewer;
