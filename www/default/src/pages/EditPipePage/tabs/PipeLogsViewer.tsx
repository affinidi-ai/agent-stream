import React from 'react';
import LogsViewer from '../../../components/shared/LogsViewer';
import { usePermissions } from '../../../context/PermissionsContext';

interface PipeLogsViewerProps {
  pipeId: string;
  pipeName?: string;
  state?: any;
  actions?: any;
}

/** Surface-scoped log tail; the appliance log is shown only to holders of `logs.view`. */
const PipeLogsViewer: React.FC<PipeLogsViewerProps> = ({ pipeId, pipeName }) => {
  const { hasPermission } = usePermissions();
  if (!hasPermission('logs.view')) {
    return null;
  }
  return <LogsViewer filterPrefix={`[PIPE:${pipeId}]`} title="Surface Logs" subtitle={pipeName} />;
};

export default PipeLogsViewer;
