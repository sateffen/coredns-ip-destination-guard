package ipdestinationguard

import (
	"github.com/coredns/coredns/plugin"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ipv4AllowListEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv4_allowlist_entries",
		Help:      "Current number of IPv4 addresses allowed by nftables.",
	})
	ipv6AllowListEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv6_allowlist_entries",
		Help:      "Current number of IPv6 addresses allowed by nftables.",
	})
	ipv4AllowListAddedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv4_allowlist_added_total",
		Help:      "Total number of IPv4 addresses added to the nftables allowlist.",
	})
	ipv6AllowListAddedTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv6_allowlist_added_total",
		Help:      "Total number of IPv6 addresses added to the nftables allowlist.",
	})
	ipv4AllowListExpiredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv4_allowlist_expired_total",
		Help:      "Total number of IPv4 addresses removed from the nftables allowlist after TTL expiry.",
	})
	ipv6AllowListExpiredTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "ipv6_allowlist_expired_total",
		Help:      "Total number of IPv6 addresses removed from the nftables allowlist after TTL expiry.",
	})
	nftablesFlushErrorsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: plugin.Namespace,
		Subsystem: pluginName,
		Name:      "nftables_flush_errors_total",
		Help:      "Total number of nftables flush errors encountered when writing allowlist changes.",
	})
)
