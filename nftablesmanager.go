package ipdestinationguard

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
)

// This local struct represents data of an route to allow in NFTables.
// This is only used locally by the NFTablesManager.syncChannel for transmitting data in a structured way.
type allowRoute struct {
	validUnitl time.Time
	ipAddress  net.IP
}

// An destination-guard manager that implements guarding with NFTables.
type NFTablesManager struct {
	nlInterface    *nftables.Conn
	ipv4AllowSet   *nftables.Set
	ipv6AllowSet   *nftables.Set
	syncChannel    chan []*allowRoute
	allowList      map[string]*allowRoute
	allowRoutePool sync.Pool
}

// Add given IPs for ttl+30 seconds to the allow traffic to them.
func (manager *NFTablesManager) AddRoutes(ips []net.IP, ttl uint32) {
	if len(ips) == 0 {
		return
	}

	validUntil := time.Now().Add(time.Duration(ttl+30) * time.Second)
	batch := make([]*allowRoute, 0, len(ips))

	for _, ip := range ips {
		newEntry := manager.allowRoutePool.Get().(*allowRoute)
		newEntry.ipAddress = ip
		newEntry.validUnitl = validUntil

		batch = append(batch, newEntry)
	}

	manager.syncChannel <- batch
}

func (manager *NFTablesManager) prepareNFTables(config *parsedConfig) error {
	targetTable := nftables.Table{
		Name:   "coredns-ip-destination-guard",
		Family: nftables.TableFamilyINet,
	}

	// Create the table and flush it
	manager.nlInterface.AddTable(&targetTable)
	manager.nlInterface.FlushTable(&targetTable)

	// Create shared IPv4/IPv6 sets
	manager.ipv4AllowSet = &nftables.Set{
		Name:    "ipv4allowlist",
		Table:   &targetTable,
		Dynamic: true,
		KeyType: nftables.TypeIPAddr,
	}

	manager.ipv6AllowSet = &nftables.Set{
		Name:    "ipv6allowlist",
		Table:   &targetTable,
		Dynamic: true,
		KeyType: nftables.TypeIP6Addr,
	}

	manager.nlInterface.AddSet(manager.ipv4AllowSet, []nftables.SetElement{})
	manager.nlInterface.AddSet(manager.ipv6AllowSet, []nftables.SetElement{})

	// Determine which chains to create based on mode
	var chainsToCreate []struct {
		name      string
		chainHook *nftables.ChainHook
	}

	switch config.mode {
	case ModeNFTLocal:
		chainsToCreate = []struct {
			name      string
			chainHook *nftables.ChainHook
		}{
			{"output", nftables.ChainHookOutput},
		}
	case ModeNFTGateway:
		chainsToCreate = []struct {
			name      string
			chainHook *nftables.ChainHook
		}{
			{"forward", nftables.ChainHookForward},
		}
	case ModeNFTBoth:
		chainsToCreate = []struct {
			name      string
			chainHook *nftables.ChainHook
		}{
			{"output", nftables.ChainHookOutput},
			{"forward", nftables.ChainHookForward},
		}
	}

	// Create all required chains and add rules
	for _, chainSpec := range chainsToCreate {
		targetChainPolicy := nftables.ChainPolicyDrop
		targetChain := nftables.Chain{
			Name:     chainSpec.name,
			Table:    &targetTable,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  chainSpec.chainHook,
			Priority: nftables.ChainPriorityFilter,
			Policy:   &targetChainPolicy,
		}
		manager.nlInterface.AddChain(&targetChain)

		// Add all rules to this chain
		if err := manager.addChainRules(&targetTable, &targetChain, chainSpec.name, config); err != nil {
			return err
		}
	}

	return manager.nlInterface.Flush()
}

// addChainRules adds all filtering rules to a specific chain
func (manager *NFTablesManager) addChainRules(targetTable *nftables.Table, targetChain *nftables.Chain, chainName string, config *parsedConfig) error {
	// Prepare permanent allow sets from config
	// Start with common allowedIPs (applied to all chains)
	ipv4PermanentAllowSetElements := []nftables.SetElement{{Key: make([]byte, 4), IntervalEnd: true}}
	ipv6PermanentAllowSetElements := []nftables.SetElement{{Key: make([]byte, 16), IntervalEnd: true}}

	// Add common allowedIPs
	for i := 0; i < len(config.allowedIPs); i += 2 {
		key := config.allowedIPs[i]
		keyEnd := config.allowedIPs[i+1]

		if len(key) == net.IPv4len {
			ipv4PermanentAllowSetElements = append(ipv4PermanentAllowSetElements, nftables.SetElement{Key: key, IntervalEnd: false})
			ipv4PermanentAllowSetElements = append(ipv4PermanentAllowSetElements, nftables.SetElement{Key: keyEnd, IntervalEnd: true})
		} else {
			ipv6PermanentAllowSetElements = append(ipv6PermanentAllowSetElements, nftables.SetElement{Key: key, IntervalEnd: false})
			ipv6PermanentAllowSetElements = append(ipv6PermanentAllowSetElements, nftables.SetElement{Key: keyEnd, IntervalEnd: true})
		}
	}

	// Add chain-specific IPs
	var chainSpecificIPs []net.IP
	if chainName == "output" && len(config.allowedLocalIPs) > 0 {
		chainSpecificIPs = config.allowedLocalIPs
	} else if chainName == "forward" && len(config.allowedGatewayIPs) > 0 {
		chainSpecificIPs = config.allowedGatewayIPs
	}

	for i := 0; i < len(chainSpecificIPs); i += 2 {
		key := chainSpecificIPs[i]
		keyEnd := chainSpecificIPs[i+1]

		if len(key) == net.IPv4len {
			ipv4PermanentAllowSetElements = append(ipv4PermanentAllowSetElements, nftables.SetElement{Key: key, IntervalEnd: false})
			ipv4PermanentAllowSetElements = append(ipv4PermanentAllowSetElements, nftables.SetElement{Key: keyEnd, IntervalEnd: true})
		} else {
			ipv6PermanentAllowSetElements = append(ipv6PermanentAllowSetElements, nftables.SetElement{Key: key, IntervalEnd: false})
			ipv6PermanentAllowSetElements = append(ipv6PermanentAllowSetElements, nftables.SetElement{Key: keyEnd, IntervalEnd: true})
		}
	}

	// region drop ct invalid traffc
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 0x1,
			},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            0x4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitINVALID),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpNeq,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})
	// endregion

	// region accept ct establised or related traffc
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Ct{
				Key:      expr.CtKeySTATE,
				Register: 0x1,
			},
			&expr.Bitwise{
				SourceRegister: 0x1,
				DestRegister:   0x1,
				Len:            0x4,
				Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
				Xor:            binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpNeq,
				Data:     binaryutil.NativeEndian.PutUint32(0),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	// endregion

	// region accept localhost traffic
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyOIF,
				Register: 0x1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 0x1,
				Data:     binaryutil.NativeEndian.PutUint32(0x1),
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	// endregion

	// region allow necessary ICMPv6
	icmpv6TypeAllowSet := nftables.Set{
		Table:     targetTable,
		Anonymous: true,
		Constant:  true,
		KeyType:   nftables.TypeICMP6Type,
	}
	manager.nlInterface.AddSet(&icmpv6TypeAllowSet, []nftables.SetElement{
		{Key: []byte{0x85}}, // nd-router-solicit   = 0x85
		{Key: []byte{0x86}}, // nd-router-advert    = 0x86
		{Key: []byte{0x87}}, // nd-neighbor-solicit = 0x87
		{Key: []byte{0x88}}, // nd-neighbor-advert  = 0x88
	})
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyL4PROTO,
				Register: 0x1,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 0x1,
				Data:     binaryutil.NativeEndian.PutUint32(0x3a),
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseTransportHeader,
				Offset:        0,
				Len:           1,
				DestRegister:  0x1,
			},
			&expr.Lookup{
				SourceRegister: 0x1,
				SetID:          icmpv6TypeAllowSet.ID,
				SetName:        icmpv6TypeAllowSet.Name,
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	// endregion

	// region allow permanent allowlisted ipv4 traffic
	if len(ipv4PermanentAllowSetElements) > 1 {
		ipv4PermanentAllowSet := nftables.Set{
			Table:     targetTable,
			Anonymous: true,
			Constant:  true,
			Interval:  true,
			KeyType:   nftables.TypeIPAddr,
		}
		manager.nlInterface.AddSet(&ipv4PermanentAllowSet, ipv4PermanentAllowSetElements)
		manager.nlInterface.AddRule(&nftables.Rule{
			Table: targetTable,
			Chain: targetChain,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyNFPROTO,
					Register: 0x1,
				},
				&expr.Cmp{
					Register: 0x1,
					Op:       expr.CmpOpEq,
					Data:     binaryutil.NativeEndian.PutUint32(0x2),
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        16,
					Len:           4,
					DestRegister:  0x1,
				},
				&expr.Lookup{
					SourceRegister: 0x1,
					SetID:          ipv4PermanentAllowSet.ID,
					SetName:        ipv4PermanentAllowSet.Name,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}
	// endregion

	// region allow permanent allowlisted ipv6 traffic
	if len(ipv6PermanentAllowSetElements) > 1 {
		ipv6PermanentAllowSet := nftables.Set{
			Table:     targetTable,
			Anonymous: true,
			Constant:  true,
			Interval:  true,
			KeyType:   nftables.TypeIP6Addr,
		}
		manager.nlInterface.AddSet(&ipv6PermanentAllowSet, ipv6PermanentAllowSetElements)
		manager.nlInterface.AddRule(&nftables.Rule{
			Table: targetTable,
			Chain: targetChain,
			Exprs: []expr.Any{
				&expr.Meta{
					Key:      expr.MetaKeyNFPROTO,
					Register: 0x1,
				},
				&expr.Cmp{
					Register: 0x1,
					Op:       expr.CmpOpEq,
					Data:     binaryutil.NativeEndian.PutUint32(0xa),
				},
				&expr.Payload{
					OperationType: expr.PayloadLoad,
					Base:          expr.PayloadBaseNetworkHeader,
					Offset:        24,
					Len:           16,
					DestRegister:  0x1,
				},
				&expr.Lookup{
					SourceRegister: 0x1,
					SetID:          ipv6PermanentAllowSet.ID,
					SetName:        ipv6PermanentAllowSet.Name,
				},
				&expr.Verdict{
					Kind: expr.VerdictAccept,
				},
			},
		})
	}
	// endregion

	// region allow temporary allowlisted ipv4 traffic
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 0x1,
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(0x2),
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        16,
				Len:           4,
				DestRegister:  0x1,
			},
			&expr.Lookup{
				SourceRegister: 0x1,
				SetID:          manager.ipv4AllowSet.ID,
				SetName:        manager.ipv4AllowSet.Name,
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	// endregion

	// region allow temporary allowlisted ipv6 traffic
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Meta{
				Key:      expr.MetaKeyNFPROTO,
				Register: 0x1,
			},
			&expr.Cmp{
				Register: 0x1,
				Op:       expr.CmpOpEq,
				Data:     binaryutil.NativeEndian.PutUint32(0xa),
			},
			&expr.Payload{
				OperationType: expr.PayloadLoad,
				Base:          expr.PayloadBaseNetworkHeader,
				Offset:        24,
				Len:           16,
				DestRegister:  0x1,
			},
			&expr.Lookup{
				SourceRegister: 0x1,
				SetID:          manager.ipv6AllowSet.ID,
				SetName:        manager.ipv6AllowSet.Name,
			},
			&expr.Verdict{
				Kind: expr.VerdictAccept,
			},
		},
	})
	// endregion

	// region reject all other traffic
	manager.nlInterface.AddRule(&nftables.Rule{
		Table: targetTable,
		Chain: targetChain,
		Exprs: []expr.Any{
			&expr.Reject{
				Type: 0x2, // icmpx
				Code: 0x3, // admin-prohibited
			},
		},
	})
	// endregion

	return nil
}

// Reads all SetElements for given set and adds them to the local allowList.
func (manager *NFTablesManager) recoverExistingSetEntries(nftSet *nftables.Set) error {
	existingEntries, err := manager.nlInterface.GetSetElements(nftSet)
	if err != nil {
		return err
	}

	for _, setEntry := range existingEntries {
		allowListEntry := manager.allowRoutePool.Get().(*allowRoute)

		allowListEntry.ipAddress = net.IP(setEntry.Key)
		allowListEntry.validUnitl = time.Now().Add(330 * time.Second)

		manager.allowList[allowListEntry.ipAddress.String()] = allowListEntry
	}

	return nil
}

// This function is a special handler function managing the current allowed entries
// in nftables. This function expects to run as singleton go-routine.
func (manager *NFTablesManager) manageAllowList() {
	gcTicker := time.NewTicker(30 * time.Second)

	for {
		select {
		case newBatch := <-manager.syncChannel:
			var ipv4ToAdd []nftables.SetElement
			var ipv6ToAdd []nftables.SetElement

			for _, newEntry := range newBatch {
				ipAsString := newEntry.ipAddress.String()
				existingRoute, exists := manager.allowList[ipAsString]

				if exists {
					if existingRoute.validUnitl.Before(newEntry.validUnitl) {
						existingRoute.validUnitl = newEntry.validUnitl
					}
					manager.allowRoutePool.Put(newEntry)
					continue
				}

				if len(newEntry.ipAddress) == net.IPv4len {
					ipv4ToAdd = append(ipv4ToAdd, nftables.SetElement{Key: newEntry.ipAddress})
				} else if len(newEntry.ipAddress) == net.IPv6len {
					ipv6ToAdd = append(ipv6ToAdd, nftables.SetElement{Key: newEntry.ipAddress})
				} else {
					log.Errorf("Received invalid ip address: %v", newEntry.ipAddress)
					manager.allowRoutePool.Put(newEntry)
					continue
				}

				manager.allowList[ipAsString] = newEntry
			}

			if len(ipv4ToAdd) > 0 {
				manager.nlInterface.SetAddElements(manager.ipv4AllowSet, ipv4ToAdd)
			}

			if len(ipv6ToAdd) > 0 {
				manager.nlInterface.SetAddElements(manager.ipv6AllowSet, ipv6ToAdd)
			}

			if len(ipv4ToAdd) > 0 || len(ipv6ToAdd) > 0 {
				if err := manager.nlInterface.Flush(); err != nil {
					log.Errorf("Writing to NFTables failed: %v", err)
				}
			}

		case <-gcTicker.C:
			var ipv4ToDelete []nftables.SetElement
			var ipv6ToDelete []nftables.SetElement
			now := time.Now()
			log.Debug("Executing NFTables GC")

			for key, listEntry := range manager.allowList {
				if now.After(listEntry.validUnitl) {
					if len(listEntry.ipAddress) == net.IPv4len {
						ipv4ToDelete = append(ipv4ToDelete, nftables.SetElement{Key: listEntry.ipAddress})
					} else if len(listEntry.ipAddress) == net.IPv6len {
						ipv6ToDelete = append(ipv6ToDelete, nftables.SetElement{Key: listEntry.ipAddress})
					}

					delete(manager.allowList, key)
					manager.allowRoutePool.Put(listEntry)
				}
			}

			if len(ipv4ToDelete) > 0 {
				manager.nlInterface.SetDeleteElements(manager.ipv4AllowSet, ipv4ToDelete)
			}

			if len(ipv6ToDelete) > 0 {
				manager.nlInterface.SetDeleteElements(manager.ipv6AllowSet, ipv6ToDelete)
			}

			if len(ipv4ToDelete) > 0 || len(ipv6ToDelete) > 0 {
				if err := manager.nlInterface.Flush(); err != nil {
					log.Errorf("Writing to NFTables failed (lists might be out of sync): %v", err)
				}
			}
		}
	}
}

func NewNFTablesManager(config *parsedConfig) (*NFTablesManager, error) {
	nlInterface, err := nftables.New(
		nftables.AsLasting(),
	)

	if err != nil {
		return nil, fmt.Errorf("error creating nftables netlink interface: %w", err)
	}

	manager := &NFTablesManager{
		nlInterface:    nlInterface,
		ipv4AllowSet:   nil,
		ipv6AllowSet:   nil,
		syncChannel:    make(chan []*allowRoute),
		allowList:      make(map[string]*allowRoute),
		allowRoutePool: sync.Pool{New: func() interface{} { return &allowRoute{} }},
	}

	if err := manager.prepareNFTables(config); err != nil {
		return nil, fmt.Errorf("error flushing necessary table and chain to nftables: %w", err)
	}

	if err := manager.recoverExistingSetEntries(manager.ipv4AllowSet); err != nil {
		return nil, fmt.Errorf("error recovering ipv4 set entries: %w", err)
	}

	if err := manager.recoverExistingSetEntries(manager.ipv6AllowSet); err != nil {
		return nil, fmt.Errorf("error recovering ipv6 set entries: %w", err)
	}

	go manager.manageAllowList()

	return manager, nil
}
