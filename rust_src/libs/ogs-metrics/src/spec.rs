//! Metric specification
//!
//! This module provides metric specifications that define the structure
//! of metrics (name, description, labels, type).

use crate::{
    MAX_LABELS,
    types::{MetricType, HistogramBucketParams},
};

/// Metric specification
/// 
/// Defines the structure of a metric including its name, description,
/// type, labels, and initial value.
#[derive(Debug, Clone)]
pub struct MetricsSpec {
    /// Metric type (counter, gauge, histogram)
    metric_type: MetricType,
    /// Metric name
    name: String,
    /// Metric description
    description: String,
    /// Initial value for the metric
    initial_val: i64,
    /// Number of labels
    num_labels: usize,
    /// Label names
    labels: Vec<String>,
    /// Histogram bucket parameters (only for histogram type)
    histogram_params: Option<HistogramBucketParams>,
}

impl MetricsSpec {
    /// Create a new metric specification
    /// 
    /// # Arguments
    /// 
    /// * `metric_type` - The type of metric (Counter, Gauge, Histogram)
    /// * `name` - The metric name
    /// * `description` - Human-readable description
    /// * `initial_val` - Initial value (used for gauges)
    /// * `labels` - Label names for this metric
    /// * `histogram_params` - Histogram bucket parameters (required for Histogram type)
    /// 
    /// # Panics
    /// 
    /// Panics if more than MAX_LABELS labels are provided.
    pub fn new(
        metric_type: MetricType,
        name: &str,
        description: &str,
        initial_val: i64,
        labels: &[&str],
        histogram_params: Option<HistogramBucketParams>,
    ) -> Self {
        assert!(labels.len() <= MAX_LABELS, "Too many labels (max {})", MAX_LABELS);
        
        if metric_type == MetricType::Histogram {
            assert!(histogram_params.is_some(), "Histogram metrics require bucket parameters");
        }

        MetricsSpec {
            metric_type,
            name: name.to_string(),
            description: description.to_string(),
            initial_val,
            num_labels: labels.len(),
            labels: labels.iter().map(|s| s.to_string()).collect(),
            histogram_params,
        }
    }

    /// Create a counter metric specification
    pub fn counter(name: &str, description: &str, labels: &[&str]) -> Self {
        Self::new(MetricType::Counter, name, description, 0, labels, None)
    }

    /// Create a gauge metric specification
    pub fn gauge(name: &str, description: &str, initial_val: i64, labels: &[&str]) -> Self {
        Self::new(MetricType::Gauge, name, description, initial_val, labels, None)
    }

    /// Create a histogram metric specification with linear buckets
    pub fn histogram_linear(
        name: &str,
        description: &str,
        labels: &[&str],
        start: f64,
        width: f64,
        count: usize,
    ) -> Self {
        Self::new(
            MetricType::Histogram,
            name,
            description,
            0,
            labels,
            Some(HistogramBucketParams::linear(start, width, count)),
        )
    }

    /// Create a histogram metric specification with exponential buckets
    pub fn histogram_exponential(
        name: &str,
        description: &str,
        labels: &[&str],
        start: f64,
        factor: f64,
        count: usize,
    ) -> Self {
        Self::new(
            MetricType::Histogram,
            name,
            description,
            0,
            labels,
            Some(HistogramBucketParams::exponential(start, factor, count)),
        )
    }

    /// Create a histogram metric specification with variable buckets
    pub fn histogram_variable(
        name: &str,
        description: &str,
        labels: &[&str],
        buckets: Vec<f64>,
    ) -> Self {
        Self::new(
            MetricType::Histogram,
            name,
            description,
            0,
            labels,
            Some(HistogramBucketParams::variable(buckets)),
        )
    }

    /// Get the metric type
    pub fn metric_type(&self) -> MetricType {
        self.metric_type
    }

    /// Get the metric name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the metric description
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Get the initial value
    pub fn initial_val(&self) -> i64 {
        self.initial_val
    }

    /// Get the number of labels
    pub fn num_labels(&self) -> usize {
        self.num_labels
    }

    /// Get the label names
    pub fn labels(&self) -> &[String] {
        &self.labels
    }

    /// Get the histogram bucket parameters
    pub fn histogram_params(&self) -> Option<&HistogramBucketParams> {
        self.histogram_params.as_ref()
    }

    /// Check if this is a counter metric
    pub fn is_counter(&self) -> bool {
        self.metric_type == MetricType::Counter
    }

    /// Check if this is a gauge metric
    pub fn is_gauge(&self) -> bool {
        self.metric_type == MetricType::Gauge
    }

    /// Check if this is a histogram metric
    pub fn is_histogram(&self) -> bool {
        self.metric_type == MetricType::Histogram
    }
}

/// Metric specification pool
pub struct SpecPool {
    specs: Vec<MetricsSpec>,
    capacity: usize,
}

impl SpecPool {
    /// Create a new spec pool
    pub fn new(capacity: usize) -> Self {
        SpecPool {
            specs: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Add a spec to the pool
    pub fn add(&mut self, spec: MetricsSpec) -> Option<&MetricsSpec> {
        if self.specs.len() >= self.capacity {
            return None;
        }
        
        self.specs.push(spec);
        self.specs.last()
    }

    /// Remove a spec by name
    pub fn remove(&mut self, name: &str) -> Option<MetricsSpec> {
        if let Some(pos) = self.specs.iter().position(|s| s.name() == name) {
            Some(self.specs.remove(pos))
        } else {
            None
        }
    }

    /// Find a spec by name
    pub fn find(&self, name: &str) -> Option<&MetricsSpec> {
        self.specs.iter().find(|s| s.name() == name)
    }

    /// Get all specs
    pub fn specs(&self) -> &[MetricsSpec] {
        &self.specs
    }

    /// Get the number of specs
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Clear all specs
    pub fn clear(&mut self) {
        self.specs.clear();
    }
}

impl Default for SpecPool {
    fn default() -> Self {
        Self::new(256)
    }
}
