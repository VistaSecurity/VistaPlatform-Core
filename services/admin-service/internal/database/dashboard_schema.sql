-- Dashboard metrics schema for enhanced analytics and historical data
-- This schema supports real-time dashboard metrics and historical trend analysis

-- Dashboard metrics table for storing aggregated metrics
CREATE TABLE IF NOT EXISTS dashboard_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_type VARCHAR(50) NOT NULL, -- 'platform', 'usage', 'performance', 'geographic'
    metric_name VARCHAR(100) NOT NULL, -- 'active_tenants', 'api_calls', 'response_time', etc.
    metric_value DECIMAL(15,4) NOT NULL,
    metric_unit VARCHAR(20), -- 'count', 'ms', 'mb', 'percent', etc.
    metadata JSONB, -- Additional metric-specific data
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for efficient querying by metric type and time
CREATE INDEX IF NOT EXISTS idx_dashboard_metrics_type_time 
ON dashboard_metrics (metric_type, timestamp DESC);

-- Index for metric name queries
CREATE INDEX IF NOT EXISTS idx_dashboard_metrics_name_time 
ON dashboard_metrics (metric_name, timestamp DESC);

-- API usage tracking table for detailed API analytics
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER NOT NULL,
    response_time_ms INTEGER NOT NULL,
    user_id UUID,
    tenant_id UUID,
    ip_address INET,
    user_agent TEXT,
    request_size_bytes INTEGER,
    response_size_bytes INTEGER,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for API usage analytics
CREATE INDEX IF NOT EXISTS idx_api_usage_endpoint_time 
ON api_usage_logs (endpoint, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_api_usage_tenant_time 
ON api_usage_logs (tenant_id, timestamp DESC);

-- System health metrics table
CREATE TABLE IF NOT EXISTS system_health_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_name VARCHAR(100) NOT NULL,
    health_status VARCHAR(20) NOT NULL, -- 'healthy', 'degraded', 'down'
    response_time_ms INTEGER,
    error_count INTEGER DEFAULT 0,
    memory_usage_mb INTEGER,
    cpu_usage_percent DECIMAL(5,2),
    disk_usage_percent DECIMAL(5,2),
    active_connections INTEGER,
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for system health queries
CREATE INDEX IF NOT EXISTS idx_system_health_service_time 
ON system_health_metrics (service_name, timestamp DESC);

-- Feature adoption tracking table
CREATE TABLE IF NOT EXISTS feature_adoption_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    feature_name VARCHAR(100) NOT NULL,
    tenant_id UUID,
    user_id UUID,
    action VARCHAR(50) NOT NULL, -- 'view', 'use', 'configure', etc.
    session_id VARCHAR(100),
    metadata JSONB,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for feature adoption analytics
CREATE INDEX IF NOT EXISTS idx_feature_adoption_feature_time 
ON feature_adoption_metrics (feature_name, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_feature_adoption_tenant_time 
ON feature_adoption_metrics (tenant_id, timestamp DESC);

-- Geographic data table for tenant location tracking
CREATE TABLE IF NOT EXISTS tenant_geographic_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    country_code VARCHAR(2),
    region VARCHAR(100),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    timezone VARCHAR(50),
    is_primary BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for geographic queries
CREATE INDEX IF NOT EXISTS idx_tenant_geo_tenant_id 
ON tenant_geographic_data (tenant_id);

CREATE INDEX IF NOT EXISTS idx_tenant_geo_country 
ON tenant_geographic_data (country_code);

-- Dashboard cache table for storing pre-computed dashboard data
CREATE TABLE IF NOT EXISTS dashboard_cache (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    cache_key VARCHAR(255) NOT NULL UNIQUE,
    cache_data JSONB NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- Index for cache cleanup
CREATE INDEX IF NOT EXISTS idx_dashboard_cache_expires 
ON dashboard_cache (expires_at);

-- Function to clean up expired cache entries
CREATE OR REPLACE FUNCTION cleanup_expired_dashboard_cache()
RETURNS void AS $$
BEGIN
    DELETE FROM dashboard_cache WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to get platform metrics for a time range
CREATE OR REPLACE FUNCTION get_platform_metrics(
    p_metric_type VARCHAR(50),
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE
)
RETURNS TABLE (
    metric_name VARCHAR(100),
    metric_value DECIMAL(15,4),
    metric_unit VARCHAR(20),
    timestamp TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        dm.metric_name,
        dm.metric_value,
        dm.metric_unit,
        dm.timestamp
    FROM dashboard_metrics dm
    WHERE dm.metric_type = p_metric_type
    AND dm.timestamp BETWEEN p_start_time AND p_end_time
    ORDER BY dm.timestamp DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get API usage statistics
CREATE OR REPLACE FUNCTION get_api_usage_stats(
    p_start_time TIMESTAMP WITH TIME ZONE,
    p_end_time TIMESTAMP WITH TIME ZONE
)
RETURNS TABLE (
    endpoint VARCHAR(255),
    method VARCHAR(10),
    total_requests BIGINT,
    avg_response_time DECIMAL(10,2),
    error_count BIGINT,
    success_rate DECIMAL(5,2)
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        aul.endpoint,
        aul.method,
        COUNT(*) as total_requests,
        AVG(aul.response_time_ms) as avg_response_time,
        COUNT(*) FILTER (WHERE aul.status_code >= 400) as error_count,
        (COUNT(*) FILTER (WHERE aul.status_code < 400) * 100.0 / COUNT(*)) as success_rate
    FROM api_usage_logs aul
    WHERE aul.timestamp BETWEEN p_start_time AND p_end_time
    GROUP BY aul.endpoint, aul.method
    ORDER BY total_requests DESC;
END;
$$ LANGUAGE plpgsql;

-- Function to get system health summary
CREATE OR REPLACE FUNCTION get_system_health_summary()
RETURNS TABLE (
    service_name VARCHAR(100),
    health_status VARCHAR(20),
    avg_response_time DECIMAL(10,2),
    error_rate DECIMAL(5,2),
    last_check TIMESTAMP WITH TIME ZONE
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        shm.service_name,
        shm.health_status,
        AVG(shm.response_time_ms) as avg_response_time,
        (COUNT(*) FILTER (WHERE shm.health_status = 'down') * 100.0 / COUNT(*)) as error_rate,
        MAX(shm.timestamp) as last_check
    FROM system_health_metrics shm
    WHERE shm.timestamp > NOW() - INTERVAL '1 hour'
    GROUP BY shm.service_name, shm.health_status
    ORDER BY shm.service_name;
END;
$$ LANGUAGE plpgsql;

-- Insert some sample data for testing
INSERT INTO dashboard_metrics (metric_type, metric_name, metric_value, metric_unit, timestamp) VALUES
('platform', 'active_tenants', 45, 'count', NOW() - INTERVAL '1 hour'),
('platform', 'total_users', 1200, 'count', NOW() - INTERVAL '1 hour'),
('platform', 'system_uptime', 99.9, 'percent', NOW() - INTERVAL '1 hour'),
('usage', 'api_calls_total', 15000, 'count', NOW() - INTERVAL '1 hour'),
('usage', 'data_ingestion_rate', 150.5, 'mb_per_hour', NOW() - INTERVAL '1 hour'),
('performance', 'avg_response_time', 150.5, 'ms', NOW() - INTERVAL '1 hour'),
('performance', 'error_rate', 0.1, 'percent', NOW() - INTERVAL '1 hour');

-- Insert sample API usage data
INSERT INTO api_usage_logs (endpoint, method, status_code, response_time_ms, tenant_id, timestamp) VALUES
('/api/v1/inventory-service/assets', 'GET', 200, 120, gen_random_uuid(), NOW() - INTERVAL '30 minutes'),
('/api/v1/sensor-manager/sensors', 'GET', 200, 95, gen_random_uuid(), NOW() - INTERVAL '25 minutes'),
('/api/v1/report-generator/reports', 'POST', 201, 250, gen_random_uuid(), NOW() - INTERVAL '20 minutes'),
('/api/v1/admin-service/stats', 'GET', 200, 80, gen_random_uuid(), NOW() - INTERVAL '15 minutes');

-- Insert sample system health data
INSERT INTO system_health_metrics (service_name, health_status, response_time_ms, memory_usage_mb, cpu_usage_percent, timestamp) VALUES
('admin-service', 'healthy', 80, 256, 15.5, NOW() - INTERVAL '10 minutes'),
('inventory-service', 'healthy', 120, 512, 25.2, NOW() - INTERVAL '10 minutes'),
('sensor-manager', 'healthy', 95, 384, 18.7, NOW() - INTERVAL '10 minutes'),
('report-generator', 'healthy', 250, 640, 35.1, NOW() - INTERVAL '10 minutes');

-- Insert sample feature adoption data
INSERT INTO feature_adoption_metrics (feature_name, tenant_id, user_id, action, timestamp) VALUES
('Asset Management', gen_random_uuid(), gen_random_uuid(), 'view', NOW() - INTERVAL '1 hour'),
('Sensor Monitoring', gen_random_uuid(), gen_random_uuid(), 'use', NOW() - INTERVAL '45 minutes'),
('Compliance Reporting', gen_random_uuid(), gen_random_uuid(), 'configure', NOW() - INTERVAL '30 minutes'),
('Admin Dashboard', gen_random_uuid(), gen_random_uuid(), 'view', NOW() - INTERVAL '15 minutes');
