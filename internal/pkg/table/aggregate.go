// Copyright (C) 2025 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package table

import (
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// AggregateRoute represents a single configured aggregate route
type AggregateRoute struct {
	prefix         netip.Prefix
	family         bgp.Family
	summaryOnly    bool
	policyName     string
	contributors   map[string]*Path // component routes contributing (key is path identifier)
	aggregatePath  *Path            // the generated aggregate route
	lastUpdate     time.Time
}

// AggregateManager manages aggregate route generation and maintenance
type AggregateManager struct {
	aggregates map[bgp.Family]map[string]*AggregateRoute // family -> prefix string -> aggregate
	policy     *RoutingPolicy
	peerInfo   *PeerInfo // local peer info for generating aggregate paths
	logger     *slog.Logger
}

// NewAggregateManager creates a new aggregate route manager
func NewAggregateManager(logger *slog.Logger, policy *RoutingPolicy, peerInfo *PeerInfo) *AggregateManager {
	return &AggregateManager{
		aggregates: make(map[bgp.Family]map[string]*AggregateRoute),
		policy:     policy,
		peerInfo:   peerInfo,
		logger:     logger,
	}
}

// AddAggregate adds a new aggregate route configuration
func (m *AggregateManager) AddAggregate(family bgp.Family, prefix netip.Prefix, summaryOnly bool, policyName string) error {
	if _, ok := m.aggregates[family]; !ok {
		m.aggregates[family] = make(map[string]*AggregateRoute)
	}

	prefixStr := prefix.String()
	if _, exists := m.aggregates[family][prefixStr]; exists {
		return fmt.Errorf("aggregate %s already exists for family %s", prefixStr, family)
	}

	m.logger.Info("Adding aggregate route",
		slog.String("Topic", "Aggregate"),
		slog.String("Family", family.String()),
		slog.String("Prefix", prefixStr),
		slog.Bool("SummaryOnly", summaryOnly),
		slog.String("Policy", policyName),
	)

	m.aggregates[family][prefixStr] = &AggregateRoute{
		prefix:       prefix,
		family:       family,
		summaryOnly:  summaryOnly,
		policyName:   policyName,
		contributors: make(map[string]*Path),
		lastUpdate:   time.Now(),
	}

	return nil
}

// DeleteAggregate removes an aggregate route configuration
func (m *AggregateManager) DeleteAggregate(family bgp.Family, prefix netip.Prefix) error {
	prefixStr := prefix.String()

	if familyAggs, ok := m.aggregates[family]; ok {
		if _, exists := familyAggs[prefixStr]; exists {
			m.logger.Info("Deleting aggregate route",
				slog.String("Topic", "Aggregate"),
				slog.String("Family", family.String()),
				slog.String("Prefix", prefixStr),
			)
			delete(familyAggs, prefixStr)
			if len(familyAggs) == 0 {
				delete(m.aggregates, family)
			}
			return nil
		}
	}

	return fmt.Errorf("aggregate %s not found for family %s", prefixStr, family)
}

// GetAggregates returns all configured aggregates for a family
func (m *AggregateManager) GetAggregates(family bgp.Family) []*AggregateRoute {
	if familyAggs, ok := m.aggregates[family]; ok {
		result := make([]*AggregateRoute, 0, len(familyAggs))
		for _, agg := range familyAggs {
			result = append(result, agg)
		}
		return result
	}
	return nil
}

// GetAllAggregates returns all configured aggregates across all families
func (m *AggregateManager) GetAllAggregates() map[bgp.Family][]*AggregateRoute {
	result := make(map[bgp.Family][]*AggregateRoute)
	for family, familyAggs := range m.aggregates {
		aggs := make([]*AggregateRoute, 0, len(familyAggs))
		for _, agg := range familyAggs {
			aggs = append(aggs, agg)
		}
		result[family] = aggs
	}
	return result
}

// shouldContribute determines if a path should contribute to an aggregate
func (m *AggregateManager) shouldContribute(path *Path, agg *AggregateRoute) bool {
	// Don't include withdrawn paths
	if path.IsWithdraw {
		return false
	}

	// Don't include aggregate paths themselves
	if path.IsLocal() && path.GetNlri() != nil {
		// Check if this is an aggregate-generated path
		if _, ok := path.GetNlri().(*bgp.IPAddrPrefix); ok {
			// Simple check: if it has ATOMIC_AGGREGATE attribute, it's likely an aggregate
			for _, attr := range path.GetPathAttrs() {
				if _, ok := attr.(*bgp.PathAttributeAtomicAggregate); ok {
					return false
				}
			}
		}
	}

	// Check if the path's prefix is covered by the aggregate
	nlri := path.GetNlri()
	var pathPrefix netip.Prefix

	switch n := nlri.(type) {
	case *bgp.IPAddrPrefix:
		pathPrefix = n.Prefix
	default:
		// Unsupported NLRI type for aggregation
		return false
	}

	// Check if path prefix is more specific than aggregate prefix
	// (i.e., covered by the aggregate)
	if !agg.prefix.Contains(pathPrefix.Addr()) {
		m.logger.Debug("Path not contained in aggregate prefix",
			slog.String("Topic", "Aggregate"),
			slog.String("PathPrefix", pathPrefix.String()),
			slog.String("AggPrefix", agg.prefix.String()),
		)
		return false
	}

	// The path prefix must be more specific (not equal)
	if pathPrefix.Bits() <= agg.prefix.Bits() {
		m.logger.Debug("Path not more specific than aggregate",
			slog.String("Topic", "Aggregate"),
			slog.String("PathPrefix", pathPrefix.String()),
			slog.Int("PathBits", pathPrefix.Bits()),
			slog.String("AggPrefix", agg.prefix.String()),
			slog.Int("AggBits", agg.prefix.Bits()),
		)
		return false
	}

	// If a policy is configured, apply it
	if agg.policyName != "" && m.policy != nil {
		// Get policy definitions
		pols := m.policy.GetPolicy(agg.policyName)
		if len(pols) == 0 {
			m.logger.Warn("Policy not found for aggregate",
				slog.String("Topic", "Aggregate"),
				slog.String("Policy", agg.policyName),
			)
			return false
		}

		// Note: Full policy evaluation would require converting to internal Policy type
		// For now, we accept the route if the policy exists
		// Full implementation would use policy.Apply() with proper conversion
	}

	return true
}

// generateAggregatePath creates an aggregate route path
func (m *AggregateManager) generateAggregatePath(agg *AggregateRoute) *Path {
	// Create the NLRI for the aggregate
	var nlri bgp.NLRI
	family := agg.family

	switch family {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		n, err := bgp.NewIPAddrPrefix(agg.prefix)
		if err != nil {
			m.logger.Error("Failed to create NLRI for aggregate",
				slog.String("Topic", "Aggregate"),
				slog.String("Prefix", agg.prefix.String()),
				slog.Any("Error", err),
			)
			return nil
		}
		nlri = n
	default:
		m.logger.Error("Unsupported address family for aggregate",
			slog.String("Topic", "Aggregate"),
			slog.String("Family", family.String()),
		)
		return nil
	}

	// Build path attributes for the aggregate
	attrs := make([]bgp.PathAttributeInterface, 0)

	// 1. Origin: IGP (locally generated)
	attrs = append(attrs, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))

	// 2. AS_PATH: Empty (local origin)
	attrs = append(attrs, bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{}))

	// 3. Next-hop
	var nexthop netip.Addr
	if agg.prefix.Addr().Is4() {
		nexthop = netip.IPv4Unspecified()
	} else {
		nexthop = netip.IPv6Unspecified()
	}

	if family == bgp.RF_IPv4_UC {
		nh, err := bgp.NewPathAttributeNextHop(nexthop)
		if err == nil {
			attrs = append(attrs, nh)
		}
	} else {
		// For IPv6, use MP_REACH_NLRI
		mpreach, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
		attrs = append(attrs, mpreach)
	}

	// 4. Local Preference
	attrs = append(attrs, bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF))

	// 5. ATOMIC_AGGREGATE (required for aggregates)
	attrs = append(attrs, bgp.NewPathAttributeAtomicAggregate())

	// 6. AGGREGATOR attribute (optional, includes our AS and router ID)
	if m.peerInfo != nil && m.peerInfo.LocalID.IsValid() {
		aggregator, err := bgp.NewPathAttributeAggregator(m.peerInfo.LocalAS, m.peerInfo.LocalID)
		if err == nil {
			attrs = append(attrs, aggregator)
		}
	}

	// Create the aggregate path
	path := NewPath(family, m.peerInfo, bgp.PathNLRI{NLRI: nlri}, false, attrs, time.Now(), false)

	m.logger.Debug("Generated aggregate path",
		slog.String("Topic", "Aggregate"),
		slog.String("Prefix", agg.prefix.String()),
		slog.Int("Contributors", len(agg.contributors)),
	)

	return path
}

// UpdateTable processes path updates and regenerates aggregate routes as needed
func (m *AggregateManager) UpdateTable(family bgp.Family, paths []*Path) ([]*Path, error) {
	familyAggs, ok := m.aggregates[family]
	if !ok || len(familyAggs) == 0 {
		// No aggregates configured for this family
		return nil, nil
	}

	m.logger.Info("UpdateTable called for aggregates",
		slog.String("Topic", "Aggregate"),
		slog.String("Family", family.String()),
		slog.Int("Paths", len(paths)),
		slog.Int("Aggregates", len(familyAggs)),
	)

	resultPaths := make([]*Path, 0)

	// Update each aggregate
	for _, agg := range familyAggs {
		changed := false

		// Check all paths to see if they contribute
		for _, path := range paths {
			pathKey := path.GetNlri().String()

			if m.shouldContribute(path, agg) {
				// Add or update contributor
				if _, exists := agg.contributors[pathKey]; !exists {
					changed = true
					m.logger.Debug("Path contributes to aggregate",
						slog.String("Topic", "Aggregate"),
						slog.String("Path", pathKey),
						slog.String("Aggregate", agg.prefix.String()),
					)
				}
				agg.contributors[pathKey] = path
			} else {
				// Remove contributor if it was there
				if _, exists := agg.contributors[pathKey]; exists {
					changed = true
					delete(agg.contributors, pathKey)
					m.logger.Debug("Path no longer contributes to aggregate",
						slog.String("Topic", "Aggregate"),
						slog.String("Path", pathKey),
						slog.String("Aggregate", agg.prefix.String()),
					)
				}
			}
		}

		// Regenerate aggregate if it changed
		if changed || agg.aggregatePath == nil {
			if len(agg.contributors) > 0 {
				// Generate/update the aggregate path
				newPath := m.generateAggregatePath(agg)
				if newPath != nil {
					if agg.aggregatePath == nil {
						m.logger.Info("Advertising new aggregate route",
							slog.String("Topic", "Aggregate"),
							slog.String("Prefix", agg.prefix.String()),
							slog.Int("Contributors", len(agg.contributors)),
						)
					}
					agg.aggregatePath = newPath
					agg.lastUpdate = time.Now()
					resultPaths = append(resultPaths, newPath)
				}
			} else {
				// No contributors, withdraw the aggregate if it exists
				if agg.aggregatePath != nil {
					m.logger.Info("Withdrawing aggregate route (no contributors)",
						slog.String("Topic", "Aggregate"),
						slog.String("Prefix", agg.prefix.String()),
					)
					// Create a withdrawal path
					withdrawPath := agg.aggregatePath.Clone(true)
					agg.aggregatePath = nil
					resultPaths = append(resultPaths, withdrawPath)
				}
			}
		} else if agg.aggregatePath != nil {
			// No change, but include existing aggregate in result
			resultPaths = append(resultPaths, agg.aggregatePath)
		}
	}

	return resultPaths, nil
}

// GetSuppressedPaths returns paths that should be suppressed due to summary-only aggregates
func (m *AggregateManager) GetSuppressedPaths(family bgp.Family) map[string]bool {
	suppressed := make(map[string]bool)

	familyAggs, ok := m.aggregates[family]
	if !ok {
		return suppressed
	}

	for _, agg := range familyAggs {
		if !agg.summaryOnly {
			continue
		}

		// Mark all contributors as suppressed
		for pathKey := range agg.contributors {
			suppressed[pathKey] = true
		}
	}

	return suppressed
}

// GetAggregate returns a specific aggregate by prefix
func (m *AggregateManager) GetAggregate(family bgp.Family, prefix netip.Prefix) (*AggregateRoute, error) {
	if familyAggs, ok := m.aggregates[family]; ok {
		if agg, exists := familyAggs[prefix.String()]; exists {
			return agg, nil
		}
	}
	return nil, fmt.Errorf("aggregate %s not found for family %s", prefix, family)
}

// GetContributors returns the contributing paths for an aggregate
func (agg *AggregateRoute) GetContributors() []*Path {
	result := make([]*Path, 0, len(agg.contributors))
	for _, path := range agg.contributors {
		result = append(result, path)
	}
	return result
}

// GetPrefix returns the aggregate prefix
func (agg *AggregateRoute) GetPrefix() netip.Prefix {
	return agg.prefix
}

// IsSummaryOnly returns whether this aggregate is in summary-only mode
func (agg *AggregateRoute) IsSummaryOnly() bool {
	return agg.summaryOnly
}

// GetPolicyName returns the policy name configured for this aggregate
func (agg *AggregateRoute) GetPolicyName() string {
	return agg.policyName
}

// GetAggregatePath returns the generated aggregate path (or nil if not active)
func (agg *AggregateRoute) GetAggregatePath() *Path {
	return agg.aggregatePath
}
