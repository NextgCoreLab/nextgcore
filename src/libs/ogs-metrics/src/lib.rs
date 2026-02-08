//! NextGCore Metrics Collection Library
//!
//! This crate provides Prometheus metrics collection for NextGCore network functions.
//! It mirrors the interface of lib/metrics/ from the C implementation.

pub mod context;
pub mod server;
pub mod spec;
pub mod instance;
pub mod types;
pub mod otel;

pub use context::*;
pub use server::*;
pub use spec::*;
pub use instance::*;
pub use types::*;
pub use otel::*;

/// Default Prometheus HTTP port
pub const DEFAULT_PROMETHEUS_HTTP_PORT: u16 = 9090;

/// Maximum number of labels per metric
pub const MAX_LABELS: usize = 8;

/// Maximum number of variable histogram buckets
pub const OGS_METRICS_HIST_VAR_BUCKETS_MAX: usize = 10;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metric_type_creation() {
        let counter_type = MetricType::Counter;
        let gauge_type = MetricType::Gauge;
        let histogram_type = MetricType::Histogram;
        
        assert!(matches!(counter_type, MetricType::Counter));
        assert!(matches!(gauge_type, MetricType::Gauge));
        assert!(matches!(histogram_type, MetricType::Histogram));
    }

    #[test]
    fn test_histogram_bucket_params() {
        let linear = HistogramBucketParams::Linear {
            start: 0.0,
            width: 10.0,
            count: 5,
        };
        
        let exponential = HistogramBucketParams::Exponential {
            start: 1.0,
            factor: 2.0,
            count: 5,
        };
        
        let variable = HistogramBucketParams::Variable {
            buckets: vec![1.0, 5.0, 10.0, 50.0, 100.0],
        };
        
        assert!(matches!(linear, HistogramBucketParams::Linear { .. }));
        assert!(matches!(exponential, HistogramBucketParams::Exponential { .. }));
        assert!(matches!(variable, HistogramBucketParams::Variable { .. }));
    }

    #[test]
    fn test_context_initialization() {
        let _ctx = MetricsContext::new();
        assert_eq!(_ctx.metrics_port(), DEFAULT_PROMETHEUS_HTTP_PORT);
    }

    #[test]
    fn test_spec_creation() {
        let ctx = MetricsContext::new();
        
        let spec = MetricsSpec::new(
            MetricType::Counter,
            "test_counter",
            "A test counter metric",
            0,
            &[],
            None,
        );
        
        assert_eq!(spec.name(), "test_counter");
        assert_eq!(spec.description(), "A test counter metric");
        assert_eq!(spec.metric_type(), MetricType::Counter);
    }

    #[test]
    fn test_spec_with_labels() {
        let spec = MetricsSpec::new(
            MetricType::Gauge,
            "test_gauge",
            "A test gauge metric",
            100,
            &["label1", "label2"],
            None,
        );
        
        assert_eq!(spec.name(), "test_gauge");
        assert_eq!(spec.num_labels(), 2);
        assert_eq!(spec.labels(), &["label1".to_string(), "label2".to_string()]);
    }

    #[test]
    fn test_instance_operations() {
        let spec = MetricsSpec::new(
            MetricType::Gauge,
            "test_gauge_ops",
            "A test gauge for operations",
            50,
            &["env"],
            None,
        );
        
        let mut inst = MetricsInstance::new(&spec, &["production"]);
        
        // Test set
        inst.set(100);
        assert_eq!(inst.value(), 100);
        
        // Test add
        inst.add(10);
        assert_eq!(inst.value(), 110);
        
        // Test inc
        inst.inc();
        assert_eq!(inst.value(), 111);
        
        // Test dec
        inst.dec();
        assert_eq!(inst.value(), 110);
        
        // Test reset
        inst.reset();
        assert_eq!(inst.value(), 50); // Back to initial value
    }

    #[test]
    fn test_counter_operations() {
        let spec = MetricsSpec::new(
            MetricType::Counter,
            "test_counter_ops",
            "A test counter for operations",
            0,
            &[],
            None,
        );
        
        let mut inst = MetricsInstance::new(&spec, &[]);
        
        // Counter starts at 0
        assert_eq!(inst.value(), 0);
        
        // Add positive value
        inst.add(5);
        assert_eq!(inst.value(), 5);
        
        // Inc
        inst.inc();
        assert_eq!(inst.value(), 6);
    }
}
