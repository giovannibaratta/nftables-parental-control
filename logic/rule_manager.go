package logic

import (
	"errors"
	"fmt"
	"nftables-parental-control/external/nftables"
	"regexp"
)

func BlockMacAddress(macAddress string) error {
	if !isValidMacAddress(macAddress) {
		return &InvalidMacAddressError{
			Err: errors.New("invalid MAC address"),
		}
	}

	err := nftables.BlockMacAddress(macAddress)

	if err != nil {
		return err
	}

	fmt.Printf("MAC address %s blocked successfully\n", macAddress)

	return nil
}

func isValidMacAddress(mac string) bool {
	// Regular expression to match a MAC address format
	macRegex := regexp.MustCompile(`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)

	return macRegex.MatchString(mac)
}
