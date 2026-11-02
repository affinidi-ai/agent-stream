import React from 'react';

const HelpTab: React.FC = () => {
  return (
    <div className="tab-pane-content">
      <div className="mb-4">
        <h5 className="text-primary">
          <i className="fas fa-info-circle me-2"></i>
          OpenTelemetry Integration Guide
        </h5>
        <p className="text-muted">Sending Agent Stream telemetry to your observability stack</p>
      </div>

      {/* OpenTelemetry Overview */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-chart-line me-2 text-primary"></i>
            What is OpenTelemetry?
          </h6>
          <p className="mb-3">
            OpenTelemetry (OTEL) is an open-source observability framework that provides a
            standardized way to collect and export telemetry data (traces, metrics, and logs) from
            your applications. Agent Stream uses OpenTelemetry to provide comprehensive visibility
            into system behavior, performance, and reliability.
          </p>
          <div className="alert alert-info">
            <strong>Three Pillars of Observability:</strong>
            <ul className="mb-0 mt-2">
              <li>
                <strong>Traces:</strong> Track requests as they flow through the system, showing
                timing and dependencies
              </li>
              <li>
                <strong>Metrics:</strong> Measure system performance with counters, gauges, and
                histograms
              </li>
              <li>
                <strong>Logs:</strong> Capture detailed event information with structured context
              </li>
            </ul>
          </div>
        </div>
      </div>

      {/* Connecting a Collector */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-plug me-2 text-primary"></i>
            Connecting a Collector
          </h6>
          <p className="mb-3">
            Agent Stream exports traces, metrics and logs over OTLP to any OpenTelemetry Collector
            or OTLP-compatible backend that you run.
          </p>

          <div className="mb-3">
            <strong>1. Set the endpoint</strong>
            <p className="small text-muted mb-2">
              In the OpenTelemetry tab, choose OTLP / gRPC (default port 4317) or OTLP / HTTP
              (default port 4318) and enter your collector&apos;s address, for example:
            </p>
            <pre className="bg-light p-3 rounded">
              <code>https://collector.example.com:4317</code>
            </pre>
            <p className="small text-muted mb-0">
              An endpoint saved here must resolve to a public address: loopback, private, link-local
              and cloud metadata addresses are refused. For a collector on the same host or private
              network (for example a Docker service name), set <code>opentelemetry.endpoint</code>{' '}
              in <code>metrics.json</code> on the appliance with <code>opentelemetry.enabled</code>{' '}
              set to <code>true</code>; an endpoint already exported to there keeps working when you
              save other settings here.
            </p>
          </div>

          <div className="mb-3">
            <strong>2. Add authentication if your backend needs it</strong>
            <p className="small text-muted mb-0">
              Enable authentication in the OpenTelemetry tab to send an auth header with every
              export.
            </p>
          </div>

          <div className="mb-0">
            <strong>3. Test the connection</strong>
            <p className="small text-muted mb-0">
              Use the &quot;Test Connection&quot; button in the OpenTelemetry tab to check that
              Agent Stream can reach the collector. It answers only reachable or not reachable, and
              a not-reachable answer always takes the full five-second timeout. It tests a public
              address, or the collector <code>metrics.json</code> exports to with export enabled
              (which may be local or private); any other private or local address is refused,
              including one saved while export is disabled.
            </p>
          </div>
        </div>
      </div>

      {/* Cloud Integration */}
      <div className="card mb-4">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-cloud me-2 text-primary"></i>
            Cloud Platform Integration
          </h6>
          <p className="mb-3">
            The OpenTelemetry Collector can export telemetry to any OTLP-compatible backend. Popular
            enterprise platforms include:
          </p>

          <div className="row">
            <div className="col-md-4 mb-2">
              <strong>Datadog</strong>
              <p className="small text-muted mb-0">
                Full-stack observability with APM, infrastructure monitoring, and log management
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Honeycomb</strong>
              <p className="small text-muted mb-0">
                High-cardinality observability optimized for debugging complex distributed systems
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>New Relic</strong>
              <p className="small text-muted mb-0">
                Comprehensive observability platform with AI-powered insights
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>AWS CloudWatch</strong>
              <p className="small text-muted mb-0">
                Native AWS monitoring integrated with other AWS services
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Azure Monitor</strong>
              <p className="small text-muted mb-0">
                Microsoft Azure's monitoring solution with Application Insights
              </p>
            </div>
            <div className="col-md-4 mb-2">
              <strong>Google Cloud Operations</strong>
              <p className="small text-muted mb-0">
                Integrated monitoring, logging, and tracing for GCP
              </p>
            </div>
          </div>

          <div className="alert alert-info mt-3 mb-0">
            <i className="fas fa-lightbulb me-2"></i>
            <strong>Tip:</strong> Configure multiple exporters in the OTEL Collector to send
            telemetry to both local tools and cloud platforms simultaneously.
          </div>
        </div>
      </div>

      {/* Documentation Links */}
      <div className="card">
        <div className="card-body">
          <h6 className="card-title">
            <i className="fas fa-book me-2 text-primary"></i>
            Additional Resources
          </h6>
          <div className="row">
            <div className="col-md-6">
              <ul className="small mb-0">
                <li>
                  <a
                    href="https://opentelemetry.io/docs/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    OpenTelemetry Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://www.jaegertracing.io/docs/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Jaeger Documentation
                  </a>
                </li>
                <li>
                  <a href="https://prometheus.io/docs/" target="_blank" rel="noopener noreferrer">
                    Prometheus Documentation
                  </a>
                </li>
              </ul>
            </div>
            <div className="col-md-6">
              <ul className="small mb-0">
                <li>
                  <a href="https://grafana.com/docs/" target="_blank" rel="noopener noreferrer">
                    Grafana Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://grafana.com/docs/tempo/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Tempo Documentation
                  </a>
                </li>
                <li>
                  <a
                    href="https://kafka.apache.org/documentation/"
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    Apache Kafka Documentation
                  </a>
                </li>
              </ul>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default HelpTab;
