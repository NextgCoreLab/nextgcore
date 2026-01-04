//! Metric instance
//!
//! This module provides metric instances that hold actual metric values
//! with specific label values.

use std::sync::atomic::{AtomicI64, Ordering};
use crate::{
    MAX_LABELS,
    types::MetricType,
    spec::MetricsSpec,
};

/// Metric instance
/// 
/// Represents a specific instance of a metric with concrete label values.
/// For example, if a metric has labels ["method", "status"], an instance
/// might have values ["GET", "200"].
pub struct MetricsInstance {
    /// Reference to the metric specification
    spec: MetricsSpec,
    /// Number of label values
    num_labels: usize,
    /// Label values
    label_values: Vec<String>,
    /// Current value (for counters and gauges)
    value: AtomicI64,
    /// Histogram observations (for histogram type)
    histogram_observations: Vec<AtomicI64>,
    /// Histogram sum (for histogram type)
    histogram_sum: AtomicI64,
    /// Histogram count (for histogram type)
    histogram_count: AtomicI64,
}

impl MetricsInstance {
    /// Create a new metric instance
    /// 
    /// # Arguments
    /// 
    /// * `spec` - The metric specification
    /// * `label_values` - Values for each label defined in the spec
    /// 
    /// # Panics
    /// 
    /// Panics if the number of label values doesn't match the spec.
    pub fn new(spec: &MetricsSpec, label_values: &[&str]) -> Self {
        assert_eq!(
            label_values.len(),
            spec.num_labels(),
            "Number of label values must match spec"
        );
        assert!(label_values.len() <= MAX_LABELS, "Too many labels");

        let histogram_buckets = if spec.is_histogram() {
            if let Some(params) = spec.histogram_params() {
                params.generate_buckets().len()
            } else {
                0
            }
        } else {
            0
        };

        let inst = MetricsInstance {
            spec: spec.clone(),
            num_labels: label_values.len(),
            label_values: label_values.iter().map(|s| s.to_string()).collect(),
            value: AtomicI64::new(0),
            histogram_observations: (0..histogram_buckets)
                .map(|_| AtomicI64::new(0))
                .collect(),
            histogram_sum: AtomicI64::new(0),
            histogram_count: AtomicI64::new(0),
        };

        // Initialize with initial value for gauges
        if spec.is_gauge() {
            inst.value.store(spec.initial_val(), Ordering::SeqCst);
        }

        inst
    }

    /// Get the metric specification
    pub fn spec(&self) -> &MetricsSpec {
        &self.spec
    }

    /// Get the number of labels
    pub fn num_labels(&self) -> usize {
        self.num_labels
    }

    /// Get the label values
    pub fn label_values(&self) -> &[String] {
        &self.label_values
    }

    /// Get the current value
    pub fn value(&self) -> i64 {
        self.value.load(Ordering::SeqCst)
    }

    /// Set the metric value (for gauges only)
    /// 
    /// # Panics
    /// 
    /// Panics if called on a non-gauge metric.
    pub fn set(&mut self, val: i64) {
        match self.spec.metric_type() {
            MetricType::Gauge => {
                self.value.store(val, Ordering::SeqCst);
            }
            _ => {
                panic!("set() can only be called on gauge metrics");
            }
        }
    }

    /// Reset the metric to its initial value
    pub fn reset(&mut self) {
        match self.spec.metric_type() {
            MetricType::Counter => {
                // Counters reset to 0
                self.value.store(0, Ordering::SeqCst);
            }
            MetricType::Gauge => {
                // Gauges reset to initial value
                self.value.store(self.spec.initial_val(), Ordering::SeqCst);
            }
            MetricType::Histogram => {
                // Reset all histogram buckets
                for obs in &self.histogram_observations {
                    obs.store(0, Ordering::SeqCst);
                }
                self.histogram_sum.store(0, Ordering::SeqCst);
                self.histogram_count.store(0, Ordering::SeqCst);
            }
        }
    }

    /// Add a value to the metric
    /// 
    /// For counters: adds the value (must be non-negative)
    /// For gauges: adds the value (can be negative)
    /// For histograms: observes the value
    pub fn add(&mut self, val: i64) {
        match self.spec.metric_type() {
            MetricType::Counter => {
                assert!(val >= 0, "Counter values must be non-negative");
                self.value.fetch_add(val, Ordering::SeqCst);
            }
            MetricType::Gauge => {
                self.value.fetch_add(val, Ordering::SeqCst);
            }
            MetricType::Histogram => {
                self.observe(val as f64);
            }
        }
    }

    /// Increment the metric by 1
    pub fn inc(&mut self) {
        self.add(1);
    }

    /// Decrement the metric by 1 (for gauges only)
    pub fn dec(&mut self) {
        self.add(-1);
    }

    /// Observe a value for histogram metrics
    pub fn observe(&mut self, val: f64) {
        if !self.spec.is_histogram() {
            return;
        }

        if let Some(params) = self.spec.histogram_params() {
            let buckets = params.generate_buckets();
            
            // Increment the appropriate bucket(s)
            for (i, &upper_bound) in buckets.iter().enumerate() {
                if val <= upper_bound {
                    if i < self.histogram_observations.len() {
                        self.histogram_observations[i].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }

            // Update sum and count
            self.histogram_sum.fetch_add(val as i64, Ordering::SeqCst);
            self.histogram_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Get histogram sum
    pub fn histogram_sum(&self) -> i64 {
        self.histogram_sum.load(Ordering::SeqCst)
    }

    /// Get histogram count
    pub fn histogram_count(&self) -> i64 {
        self.histogram_count.load(Ordering::SeqCst)
    }

    /// Get histogram bucket counts
    pub fn histogram_buckets(&self) -> Vec<i64> {
        self.histogram_observations
            .iter()
            .map(|obs| obs.load(Ordering::SeqCst))
            .collect()
    }
}

/// Instance pool for managing metric instances
pub struct InstancePool {
    instances: Vec<MetricsInstance>,
}

impl InstancePool {
    /// Create a new instance pool
    pub fn new() -> Self {
        InstancePool {
            instances: Vec::new(),
        }
    }

    /// Add an instance to the pool
    pub fn add(&mut self, instance: MetricsInstance) -> &MetricsInstance {
        self.instances.push(instance);
        self.instances.last().unwrap()
    }

    /// Remove an instance by index
    pub fn remove(&mut self, index: usize) -> Option<MetricsInstance> {
        if index < self.instances.len() {
            Some(self.instances.remove(index))
        } else {
            None
        }
    }

    /// Find instances by spec name
    pub fn find_by_spec(&self, spec_name: &str) -> Vec<&MetricsInstance> {
        self.instances
            .iter()
            .filter(|i| i.spec().name() == spec_name)
            .collect()
    }

    /// Get all instances
    pub fn instances(&self) -> &[MetricsInstance] {
        &self.instances
    }

    /// Get mutable reference to all instances
    pub fn instances_mut(&mut self) -> &mut Vec<MetricsInstance> {
        &mut self.instances
    }

    /// Get the number of instances
    pub fn len(&self) -> usize {
        self.instances.len()
    }

    /// Check if the pool is empty
    pub fn is_empty(&self) -> bool {
        self.instances.is_empty()
    }

    /// Clear all instances
    pub fn clear(&mut self) {
        self.instances.clear();
    }
}

impl Default for InstancePool {
    fn default() -> Self {
        Self::new()
    }
}
