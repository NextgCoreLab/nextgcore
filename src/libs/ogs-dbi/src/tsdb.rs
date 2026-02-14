//! Time-Series Database Support (6G Feature - B4.5)
//!
//! This module provides time-series database operations for storing and querying
//! metrics, telemetry data, and temporal network analytics.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Time-series database errors
#[derive(Error, Debug)]
pub enum TsDbError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("Query error: {0}")]
    QueryError(String),
    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),
    #[error("Metric not found: {0}")]
    MetricNotFound(String),
}

/// Result type for time-series operations
pub type TsDbResult<T> = Result<T, TsDbError>;

/// Timestamp type (microseconds since epoch)
pub type Timestamp = i64;

/// Data point in a time series
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPoint {
    /// Timestamp
    pub timestamp: Timestamp,
    /// Value
    pub value: f64,
    /// Optional tags
    pub tags: BTreeMap<String, String>,
}

impl DataPoint {
    /// Create a new data point
    pub fn new(timestamp: Timestamp, value: f64) -> Self {
        DataPoint {
            timestamp,
            value,
            tags: BTreeMap::new(),
        }
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }
}

/// Time series metric
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeries {
    /// Metric name
    pub name: String,
    /// Measurement unit
    pub unit: Option<String>,
    /// Data points
    pub points: Vec<DataPoint>,
}

impl TimeSeries {
    /// Create a new time series
    pub fn new(name: impl Into<String>) -> Self {
        TimeSeries {
            name: name.into(),
            unit: None,
            points: Vec::new(),
        }
    }

    /// Set unit
    pub fn with_unit(mut self, unit: impl Into<String>) -> Self {
        self.unit = Some(unit.into());
        self
    }

    /// Add data point
    pub fn add_point(&mut self, point: DataPoint) {
        self.points.push(point);
        // Keep sorted by timestamp
        self.points.sort_by_key(|p| p.timestamp);
    }

    /// Get points in time range
    pub fn get_range(&self, start: Timestamp, end: Timestamp) -> Vec<&DataPoint> {
        self.points
            .iter()
            .filter(|p| p.timestamp >= start && p.timestamp <= end)
            .collect()
    }

    /// Calculate average value
    pub fn avg(&self) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }
        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        Some(sum / self.points.len() as f64)
    }

    /// Calculate min/max
    pub fn min_max(&self) -> Option<(f64, f64)> {
        if self.points.is_empty() {
            return None;
        }
        let values: Vec<f64> = self.points.iter().map(|p| p.value).collect();
        Some((
            values.iter().cloned().fold(f64::INFINITY, f64::min),
            values.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        ))
    }

    /// Calculate percentile value (0-100). Uses nearest-rank method.
    pub fn percentile(&self, pct: f64) -> Option<f64> {
        if self.points.is_empty() || !(0.0..=100.0).contains(&pct) {
            return None;
        }
        let mut sorted: Vec<f64> = self.points.iter().map(|p| p.value).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let rank = ((pct / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
        Some(sorted[rank.min(sorted.len() - 1)])
    }

    /// Standard deviation of values.
    pub fn std_dev(&self) -> Option<f64> {
        let avg = self.avg()?;
        let n = self.points.len() as f64;
        let variance: f64 = self.points.iter().map(|p| (p.value - avg).powi(2)).sum::<f64>() / n;
        Some(variance.sqrt())
    }

    /// Downsample by averaging over intervals
    pub fn downsample(&self, interval_us: i64) -> Vec<DataPoint> {
        if self.points.is_empty() {
            return Vec::new();
        }

        let mut result = Vec::new();
        let start_time = self.points[0].timestamp;
        let end_time = self.points.last().unwrap().timestamp;

        let mut current_time = start_time;
        while current_time <= end_time {
            let interval_end = current_time + interval_us;
            let points_in_interval: Vec<&DataPoint> = self.points
                .iter()
                .filter(|p| p.timestamp >= current_time && p.timestamp < interval_end)
                .collect();

            if !points_in_interval.is_empty() {
                let avg_value = points_in_interval.iter().map(|p| p.value).sum::<f64>()
                    / points_in_interval.len() as f64;
                result.push(DataPoint::new(current_time, avg_value));
            }

            current_time = interval_end;
        }

        result
    }
}

/// Time-series database client
pub struct TsDbClient {
    /// Connection endpoint
    _endpoint: String,
    /// Database name
    _database: String,
    /// In-memory storage (for testing/simulation)
    series: BTreeMap<String, TimeSeries>,
}

impl TsDbClient {
    /// Create a new client
    pub fn new(endpoint: impl Into<String>, database: impl Into<String>) -> Self {
        TsDbClient {
            _endpoint: endpoint.into(),
            _database: database.into(),
            series: BTreeMap::new(),
        }
    }

    /// Create an in-memory client (for testing)
    pub fn in_memory() -> Self {
        TsDbClient::new("memory://localhost", "metrics")
    }

    /// Write a data point
    pub fn write_point(&mut self, metric: &str, point: DataPoint) -> TsDbResult<()> {
        let series = self.series
            .entry(metric.to_string())
            .or_insert_with(|| TimeSeries::new(metric));

        series.add_point(point);
        Ok(())
    }

    /// Write multiple points
    pub fn write_points(&mut self, metric: &str, points: Vec<DataPoint>) -> TsDbResult<()> {
        for point in points {
            self.write_point(metric, point)?;
        }
        Ok(())
    }

    /// Query time series
    pub fn query(&self, metric: &str) -> TsDbResult<&TimeSeries> {
        self.series
            .get(metric)
            .ok_or_else(|| TsDbError::MetricNotFound(metric.to_string()))
    }

    /// Query time range
    pub fn query_range(
        &self,
        metric: &str,
        start: Timestamp,
        end: Timestamp,
    ) -> TsDbResult<Vec<DataPoint>> {
        let series = self.query(metric)?;

        if start > end {
            return Err(TsDbError::InvalidTimeRange(
                format!("start {start} > end {end}")
            ));
        }

        Ok(series.get_range(start, end).into_iter().cloned().collect())
    }

    /// List all metrics
    pub fn list_metrics(&self) -> Vec<String> {
        self.series.keys().cloned().collect()
    }

    /// Delete a metric
    pub fn delete_metric(&mut self, metric: &str) -> TsDbResult<()> {
        self.series.remove(metric)
            .ok_or_else(|| TsDbError::MetricNotFound(metric.to_string()))?;
        Ok(())
    }

    /// Get metric count
    pub fn metric_count(&self) -> usize {
        self.series.len()
    }

    /// Clear all data
    pub fn clear(&mut self) {
        self.series.clear();
    }

    /// Apply retention policy: remove data points older than cutoff timestamp.
    /// Returns total number of points removed across all series.
    pub fn apply_retention(&mut self, cutoff_timestamp: Timestamp) -> usize {
        let mut removed = 0;
        for series in self.series.values_mut() {
            let before = series.points.len();
            series.points.retain(|p| p.timestamp >= cutoff_timestamp);
            removed += before - series.points.len();
        }
        // Remove empty series
        self.series.retain(|_, s| !s.points.is_empty());
        removed
    }

    /// Get aggregate statistics for a metric.
    pub fn stats(&self, metric: &str) -> TsDbResult<MetricStats> {
        let series = self.query(metric)?;
        Ok(MetricStats {
            count: series.points.len(),
            avg: series.avg(),
            min_max: series.min_max(),
            p50: series.percentile(50.0),
            p95: series.percentile(95.0),
            p99: series.percentile(99.0),
            std_dev: series.std_dev(),
        })
    }
}

/// Aggregate statistics for a metric.
#[derive(Debug, Clone)]
pub struct MetricStats {
    /// Number of data points.
    pub count: usize,
    /// Average value.
    pub avg: Option<f64>,
    /// Min and max values.
    pub min_max: Option<(f64, f64)>,
    /// 50th percentile (median).
    pub p50: Option<f64>,
    /// 95th percentile.
    pub p95: Option<f64>,
    /// 99th percentile.
    pub p99: Option<f64>,
    /// Standard deviation.
    pub std_dev: Option<f64>,
}

/// Network metrics collector
pub struct NetworkMetricsCollector {
    client: TsDbClient,
}

impl NetworkMetricsCollector {
    /// Create a new collector
    pub fn new(client: TsDbClient) -> Self {
        NetworkMetricsCollector { client }
    }

    /// Record throughput
    pub fn record_throughput(&mut self, timestamp: Timestamp, value_mbps: f64, ue_id: &str) -> TsDbResult<()> {
        let point = DataPoint::new(timestamp, value_mbps)
            .with_tag("ue_id", ue_id);
        self.client.write_point("network.throughput", point)
    }

    /// Record latency
    pub fn record_latency(&mut self, timestamp: Timestamp, value_ms: f64, nf_type: &str) -> TsDbResult<()> {
        let point = DataPoint::new(timestamp, value_ms)
            .with_tag("nf_type", nf_type);
        self.client.write_point("network.latency", point)
    }

    /// Record packet loss
    pub fn record_packet_loss(&mut self, timestamp: Timestamp, loss_pct: f64, slice_id: &str) -> TsDbResult<()> {
        let point = DataPoint::new(timestamp, loss_pct)
            .with_tag("slice_id", slice_id);
        self.client.write_point("network.packet_loss", point)
    }

    /// Record energy consumption
    pub fn record_energy(&mut self, timestamp: Timestamp, watts: f64, nf_instance: &str) -> TsDbResult<()> {
        let point = DataPoint::new(timestamp, watts)
            .with_tag("nf_instance", nf_instance);
        self.client.write_point("network.energy", point)
    }

    /// Get client reference
    pub fn client(&self) -> &TsDbClient {
        &self.client
    }

    /// Get mutable client reference
    pub fn client_mut(&mut self) -> &mut TsDbClient {
        &mut self.client
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_point_creation() {
        let point = DataPoint::new(1000, 42.5);
        assert_eq!(point.timestamp, 1000);
        assert_eq!(point.value, 42.5);
    }

    #[test]
    fn test_data_point_with_tags() {
        let point = DataPoint::new(1000, 42.5)
            .with_tag("host", "server1")
            .with_tag("region", "us-west");

        assert_eq!(point.tags.len(), 2);
        assert_eq!(point.tags.get("host"), Some(&"server1".to_string()));
    }

    #[test]
    fn test_time_series_add_point() {
        let mut series = TimeSeries::new("test.metric");
        series.add_point(DataPoint::new(1000, 10.0));
        series.add_point(DataPoint::new(2000, 20.0));
        series.add_point(DataPoint::new(1500, 15.0)); // Out of order

        // Should be sorted
        assert_eq!(series.points.len(), 3);
        assert_eq!(series.points[0].timestamp, 1000);
        assert_eq!(series.points[1].timestamp, 1500);
        assert_eq!(series.points[2].timestamp, 2000);
    }

    #[test]
    fn test_time_series_get_range() {
        let mut series = TimeSeries::new("test.metric");
        series.add_point(DataPoint::new(1000, 10.0));
        series.add_point(DataPoint::new(2000, 20.0));
        series.add_point(DataPoint::new(3000, 30.0));
        series.add_point(DataPoint::new(4000, 40.0));

        let range = series.get_range(1500, 3500);
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].timestamp, 2000);
        assert_eq!(range[1].timestamp, 3000);
    }

    #[test]
    fn test_time_series_avg() {
        let mut series = TimeSeries::new("test.metric");
        series.add_point(DataPoint::new(1000, 10.0));
        series.add_point(DataPoint::new(2000, 20.0));
        series.add_point(DataPoint::new(3000, 30.0));

        assert_eq!(series.avg(), Some(20.0));
    }

    #[test]
    fn test_time_series_min_max() {
        let mut series = TimeSeries::new("test.metric");
        series.add_point(DataPoint::new(1000, 10.0));
        series.add_point(DataPoint::new(2000, 5.0));
        series.add_point(DataPoint::new(3000, 25.0));

        assert_eq!(series.min_max(), Some((5.0, 25.0)));
    }

    #[test]
    fn test_time_series_downsample() {
        let mut series = TimeSeries::new("test.metric");
        for i in 0..10 {
            series.add_point(DataPoint::new(i * 1000, i as f64 * 10.0));
        }

        // Downsample to 3-second intervals
        let downsampled = series.downsample(3000);
        assert!(downsampled.len() <= 4); // Original 10 points over 9 seconds
    }

    #[test]
    fn test_tsdb_client_write_read() {
        let mut client = TsDbClient::in_memory();

        let point = DataPoint::new(1000, 42.0);
        client.write_point("test.metric", point).unwrap();

        let series = client.query("test.metric").unwrap();
        assert_eq!(series.points.len(), 1);
        assert_eq!(series.points[0].value, 42.0);
    }

    #[test]
    fn test_tsdb_client_query_range() {
        let mut client = TsDbClient::in_memory();

        client.write_point("test.metric", DataPoint::new(1000, 10.0)).unwrap();
        client.write_point("test.metric", DataPoint::new(2000, 20.0)).unwrap();
        client.write_point("test.metric", DataPoint::new(3000, 30.0)).unwrap();

        let points = client.query_range("test.metric", 1500, 2500).unwrap();
        assert_eq!(points.len(), 1);
        assert_eq!(points[0].timestamp, 2000);
    }

    #[test]
    fn test_tsdb_client_list_metrics() {
        let mut client = TsDbClient::in_memory();

        client.write_point("metric1", DataPoint::new(1000, 1.0)).unwrap();
        client.write_point("metric2", DataPoint::new(1000, 2.0)).unwrap();
        client.write_point("metric3", DataPoint::new(1000, 3.0)).unwrap();

        let metrics = client.list_metrics();
        assert_eq!(metrics.len(), 3);
        assert!(metrics.contains(&"metric1".to_string()));
        assert!(metrics.contains(&"metric2".to_string()));
        assert!(metrics.contains(&"metric3".to_string()));
    }

    #[test]
    fn test_network_metrics_collector() {
        let mut collector = NetworkMetricsCollector::new(TsDbClient::in_memory());

        collector.record_throughput(1000, 100.5, "ue-001").unwrap();
        collector.record_latency(1000, 5.2, "AMF").unwrap();
        collector.record_packet_loss(1000, 0.01, "slice-1").unwrap();
        collector.record_energy(1000, 150.0, "amf-instance-1").unwrap();

        assert_eq!(collector.client().metric_count(), 4);
    }

    #[test]
    fn test_delete_metric() {
        let mut client = TsDbClient::in_memory();

        client.write_point("test.metric", DataPoint::new(1000, 1.0)).unwrap();
        assert!(client.query("test.metric").is_ok());

        client.delete_metric("test.metric").unwrap();
        assert!(client.query("test.metric").is_err());
    }

    #[test]
    fn test_invalid_time_range() {
        let mut client = TsDbClient::in_memory();
        client.write_point("test.metric", DataPoint::new(1000, 1.0)).unwrap();

        // Start > end should fail
        let result = client.query_range("test.metric", 2000, 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_percentile() {
        let mut series = TimeSeries::new("test");
        for i in 1..=100 {
            series.add_point(DataPoint::new(i * 1000, i as f64));
        }
        // p50 should be ~50
        let p50 = series.percentile(50.0).unwrap();
        assert!((p50 - 50.0).abs() < 2.0);
        // p99 should be ~99
        let p99 = series.percentile(99.0).unwrap();
        assert!((p99 - 99.0).abs() < 2.0);
    }

    #[test]
    fn test_std_dev() {
        let mut series = TimeSeries::new("test");
        series.add_point(DataPoint::new(1000, 10.0));
        series.add_point(DataPoint::new(2000, 10.0));
        series.add_point(DataPoint::new(3000, 10.0));
        // All same values, std dev = 0
        assert!((series.std_dev().unwrap() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_retention_policy() {
        let mut client = TsDbClient::in_memory();
        client.write_point("m1", DataPoint::new(1000, 1.0)).unwrap();
        client.write_point("m1", DataPoint::new(2000, 2.0)).unwrap();
        client.write_point("m1", DataPoint::new(3000, 3.0)).unwrap();

        let removed = client.apply_retention(2000);
        assert_eq!(removed, 1); // Only the 1000 timestamp point
        assert_eq!(client.query("m1").unwrap().points.len(), 2);
    }

    #[test]
    fn test_retention_removes_empty_series() {
        let mut client = TsDbClient::in_memory();
        client.write_point("m1", DataPoint::new(1000, 1.0)).unwrap();
        client.apply_retention(2000); // Removes all points in m1
        assert_eq!(client.metric_count(), 0);
    }

    #[test]
    fn test_metric_stats() {
        let mut client = TsDbClient::in_memory();
        for i in 1..=100 {
            client.write_point("latency", DataPoint::new(i * 1000, i as f64)).unwrap();
        }
        let stats = client.stats("latency").unwrap();
        assert_eq!(stats.count, 100);
        assert!((stats.avg.unwrap() - 50.5).abs() < 0.01);
        assert_eq!(stats.min_max.unwrap(), (1.0, 100.0));
        assert!(stats.p95.is_some());
        assert!(stats.std_dev.is_some());
    }
}
