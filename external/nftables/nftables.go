package nftables

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func BlockMacAddress(macAddress string) error {
	connection, err := nftables.New()

	if err != nil {
		return &NftError{
			Err: err,
		}
	}

	cleanTable(connection, macAddress)

	if addBlockingRule(connection, macAddress) != nil {
		return err
	}

	if connection.Flush() != nil {
		return err
	}

	return nil
}

func cleanTable(c *nftables.Conn, macAddress string) {
	tableName := sanitizeMacAddress(macAddress)
	table := &nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	}

	// Create the table to avoid non exist errors
	c.AddTable(table)
	c.DelTable(table)
}

func addBlockingRule(c *nftables.Conn, macAddress string) error {

	tableName := sanitizeMacAddress(macAddress)
	macAddressBytes, err := macAddressToBytes(macAddress)

	if err != nil || len(macAddressBytes) != 6 {
		return &NftError{
			Err: fmt.Errorf(
				"invalid mac address: %s",
				macAddress,
			),
		}
	}

	table := c.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   tableName,
	})

	inputChain := c.AddChain(&nftables.Chain{
		Name:     "block_traffic",
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
	})

	c.AddRule(&nftables.Rule{
		Table: table,
		Chain: inputChain,
		Exprs: []expr.Any{
			// Meta and Cmp are used to match an ethernet packet
			&expr.Meta{Key: expr.MetaKeyIIFTYPE, Register: 1},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     []byte{0x01, 0x00},
			},
			// Payload + Cmp are used to match the MAC address contained
			// in the link layer packet
			&expr.Payload{
				DestRegister: 1,
				Base:         expr.PayloadBaseLLHeader,
				Offset:       6,
				Len:          6,
			},
			&expr.Cmp{
				Op:       expr.CmpOpEq,
				Register: 1,
				Data:     macAddressBytes,
			},
			&expr.Counter{},
			&expr.Log{},
			&expr.Verdict{
				Kind: expr.VerdictDrop,
			},
		},
	})

	return nil
}

func sanitizeMacAddress(mac string) string {
	noUnderscore := strings.ReplaceAll(mac, ":", "_")
	return "NPC_" + strings.ToUpper(noUnderscore)
}

func macAddressToBytes(mac string) ([]byte, error) {
	macWithoutSemiColon := strings.ReplaceAll(mac, ":", "")
	macBytes, err := hex.DecodeString(macWithoutSemiColon)

	if err != nil {
		return nil, err
	}

	return macBytes, nil
}
