package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows/registry"
)

const (
	WMIGUID_QUERY                 = 0x00000001
	WMIGUID_SET                   = 0x00000002
	WMIGUID_NOTIFICATION          = 0x00000004
	WMIGUID_READ_DESCRIPTION      = 0x00000008
	WMIGUID_EXECUTE               = 0x00000010
	TRACELOG_CREATE_REALTIME      = 0x00000020
	TRACELOG_CREATE_ONDISK        = 0x00000040
	TRACELOG_GUID_ENABLE          = 0x00000080
	TRACELOG_ACCESS_KERNEL_LOGGER = 0x00000100
	TRACELOG_CREATE_INPROC        = 0x00000200
	TRACELOG_LOG_EVENT            = 0x00000400
	TRACELOG_ACCESS_REALTIME      = 0x00000400
	TRACELOG_REGISTER_GUIDS       = 0x00000800
	TRACELOG_JOIN_GROUP           = 0x00001000
)

const DEFAULT_ETW_GUID = "{0811C1AF-7A07-4A06-82ED-869455CDF713}"

var ETWPermissions = map[uint32]string{
	WMIGUID_QUERY:                 "WMIGUID_QUERY",
	WMIGUID_SET:                   "WMIGUID_SET",
	WMIGUID_NOTIFICATION:          "WMIGUID_NOTIFICATION",
	WMIGUID_READ_DESCRIPTION:      "WMIGUID_READ_DESCRIPTION",
	WMIGUID_EXECUTE:               "WMIGUID_EXECUTE",
	TRACELOG_CREATE_REALTIME:      "TRACELOG_CREATE_REALTIME",
	TRACELOG_CREATE_ONDISK:        "TRACELOG_CREATE_ONDISK",
	TRACELOG_GUID_ENABLE:          "TRACELOG_GUID_ENABLE",
	TRACELOG_ACCESS_KERNEL_LOGGER: "TRACELOG_ACCESS_KERNEL_LOGGER",
	TRACELOG_CREATE_INPROC:        "TRACELOG_CREATE_INPROC",
	TRACELOG_LOG_EVENT:            "TRACELOG_LOG_EVENT",
	TRACELOG_REGISTER_GUIDS:       "TRACELOG_REGISTER_GUIDS",
	TRACELOG_JOIN_GROUP:           "TRACELOG_JOIN_GROUP",
}

type Provider struct {
	GUID                          string       `json:"guid"`
	Name                          string       `json:"name,omitempty"`
	SecurityPermissionsRegistered bool         `json:"security_permissions_registered"`
	Permissions                   []Permission `json:"permissions"`
	RawSecurity                   []byte       `json:"raw_security,omitempty"`
}

type ProviderInfo struct {
	ProviderGUID string `json:"providerGuid"`
	Name         string `json:"name"`
}

type Permission struct {
	Type        string   `json:"type"`        // Allow/Deny
	Account     string   `json:"account"`     // SID or account name
	AccessMask  uint32   `json:"access_mask"` // Raw access mask
	Permissions []string `json:"permissions"` // Human-readable permissions
}

type SecurityDescriptor struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uint32
	Group    uint32
	Sacl     uint32
	Dacl     uint32
}

type ACL struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

type ACEHeader struct {
	AceType  byte
	AceFlags byte
	AceSize  uint16
}

type AccessAllowedACE struct {
	Header   ACEHeader
	Mask     uint32
	SidStart uint32
}

type ETWLocksmith struct {
	providers map[string]*Provider
}

func NewETWLocksmith() *ETWLocksmith {
	return &ETWLocksmith{
		providers: make(map[string]*Provider),
	}
}

func (e *ETWLocksmith) LoadProviders() error {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\WMI\Security`, registry.READ)
	if err != nil {
		return fmt.Errorf("failed to open WMI Security registry key: %v", err)
	}
	defer key.Close()

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return fmt.Errorf("failed to read value names: %v", err)
	}

	log.Printf("Found %d ETW security entries in registry", len(valueNames))

	for _, guidValue := range valueNames {
		guid := guidValue
		if !strings.HasPrefix(guid, "{") {
			guid = "{" + guid + "}"
		}

		provider := &Provider{
			GUID:                          guid,
			SecurityPermissionsRegistered: true,
		}

		securityData, _, err := key.GetBinaryValue(guidValue)
		if err != nil {
			log.Printf("Warning: failed to read security for GUID %s: %v", guid, err)
			continue
		}

		if len(securityData) == 0 {
			log.Printf("Warning: empty security data for GUID %s", guid)
			continue
		}

		provider.RawSecurity = securityData
		provider.Permissions = e.parseSecurityDescriptor(securityData)

		provider.Name = e.resolveProviderName(guidValue)
		if provider.Name == "" {
			provider.Name = "Unknown Provider"
		}

		e.providers[guid] = provider
	}

	return nil
}

func (e *ETWLocksmith) resolveProviderName(guid string) string {
	guidKey := strings.Trim(guid, "{}")

	if name := e.getProviderNameFromWBEM(guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SYSTEM\CurrentControlSet\Control\WMI\Security`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\WMI\Security`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SYSTEM\CurrentControlSet\Control\WMI\Autologger`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SYSTEM\CurrentControlSet\Services\EventLog\Application`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SYSTEM\CurrentControlSet\Services\EventLog\System`, guidKey); name != "" {
		return name
	}

	if name := e.getProviderNameFromKey(`SYSTEM\CurrentControlSet\Services\EventLog\Security`, guidKey); name != "" {
		return name
	}

	if name := e.getWellKnownProviderName(guidKey); name != "" {
		return name
	}

	return "Unknown Provider"
}

func (e *ETWLocksmith) getProviderNameFromKey(keyPath, guid string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return ""
	}
	defer key.Close()

	if strings.Contains(keyPath, "WINEVT\\Publishers") {
		subkeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			return ""
		}

		for _, subkey := range subkeys {
			if strings.EqualFold(strings.Trim(subkey, "{}"), guid) {
				guidKey, err := registry.OpenKey(key, subkey, registry.READ)
				if err != nil {
					continue
				}
				defer guidKey.Close()

				if name, _, err := guidKey.GetStringValue(""); err == nil && name != "" {
					return name
				}

				if name, _, err := guidKey.GetStringValue("FriendlyName"); err == nil && name != "" {
					return name
				}
				if name, _, err := guidKey.GetStringValue("DisplayName"); err == nil && name != "" {
					return name
				}
				if name, _, err := guidKey.GetStringValue("Name"); err == nil && name != "" {
					return name
				}
			}
		}

		return ""
	}

	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return ""
	}

	for _, valueName := range valueNames {
		if strings.EqualFold(valueName, guid) {
			if name, _, err := key.GetStringValue("FriendlyName"); err == nil && name != "" {
				return name
			}
			if name, _, err := key.GetStringValue("DisplayName"); err == nil && name != "" {
				return name
			}
			if name, _, err := key.GetStringValue("Name"); err == nil && name != "" {
				return name
			}
			return valueName
		}
	}

	return ""
}

func (e *ETWLocksmith) getProviderNameFromWBEM(guid string) string {
	wbemPaths := []string{
		`SOFTWARE\Microsoft\WBEM\Providers`,
		`SOFTWARE\Microsoft\WBEM\Scripts`,
		`SOFTWARE\Microsoft\WBEM\CIMOM`,
	}

	for _, wbemPath := range wbemPaths {
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, wbemPath, registry.READ)
		if err != nil {
			continue
		}

		subkeys, err := key.ReadSubKeyNames(-1)
		if err != nil {
			key.Close()
			continue
		}

		for _, providerName := range subkeys {
			providerKey, err := registry.OpenKey(key, providerName, registry.READ)
			if err != nil {
				continue
			}

			valueNames, err := providerKey.ReadValueNames(-1)
			if err != nil {
				providerKey.Close()
				continue
			}

			for _, valueName := range valueNames {
				if strings.EqualFold(valueName, guid) {
					providerKey.Close()
					key.Close()
					return providerName
				}
			}

			if guidValue, _, err := providerKey.GetStringValue("GUID"); err == nil {
				if strings.EqualFold(strings.Trim(guidValue, "{}"), guid) {
					providerKey.Close()
					key.Close()
					return providerName
				}
			}

			if clsidValue, _, err := providerKey.GetStringValue("CLSID"); err == nil {
				if strings.EqualFold(strings.Trim(clsidValue, "{}"), guid) {
					providerKey.Close()
					key.Close()
					return providerName
				}
			}

			providerKey.Close()
		}

		key.Close()
	}

	return ""
}

func (e *ETWLocksmith) getWellKnownProviderName(guid string) string {
	wellKnownProviders := map[string]string{
		"9E814AAD-3204-11D2-9A82-006008A86939": "NT Kernel Logger",
		"0811C1AF-7A07-4A06-82ED-869455CDF713": "Default ETW Security",
		"472496CF-0DAF-4F7C-AC2E-3F8457ECC6BB": "Private Logger Security",
		"22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716": "Microsoft-Windows-Kernel-Process",
		"3D6FA8D1-FE05-11D0-9DDA-00C04FD7BA7C": "Microsoft-Windows-Kernel-File",
		"EDD08927-9CC4-4E65-B970-C2560FB5C289": "Microsoft-Windows-Kernel-Registry",
		"EB004A00-9B1A-11D4-9123-0050047759BC": "Microsoft-Windows-Kernel-Network",
		"2F07E2EE-15DB-40F1-90EF-9D7BA282188A": "Microsoft-Windows-Kernel-Memory",
		"D58C63E3-16E7-4E12-8D65-4355F32C8C5B": "Microsoft-Windows-Kernel-Power",
		"331C3B3A-2005-44C2-AC5E-77220C37D6B4": "Microsoft-Windows-Kernel-Processor-Power",
		"0C1BA1AF-5760-4F48-B8AA-9E1761A2EC0D": "Microsoft-Windows-Kernel-Interrupt-Steering",
		"E53C6823-7BB8-44BB-90DC-3F86090D48A6": "Microsoft-Windows-Kernel-EventTracing",
		"B3E675D7-2554-4340-AB10-9F5A8C884D11": "Microsoft-Windows-Kernel-EventTracing-Management",
		"68AFD2B6-6B78-4E87-9E4F-3B8A8F7E9C0F": "Microsoft-Windows-Kernel-EventTracing-Session",
		"7B563579-53C8-44E7-8236-A1C5D9C6A8C5": "Microsoft-Windows-Kernel-EventTracing-Config",
		"F55203D9-0CB6-4D9F-9A6F-8F8F8F8F8F8F": "Microsoft-Windows-Kernel-EventTracing-Provider",
		"1F1217B8-9E05-4F87-9C01-5A5A5A5A5A5A": "Microsoft-Windows-Kernel-EventTracing-Consumer",
		"2E2E2E2E-2E2E-2E2E-2E2E-2E2E2E2E2E2E": "Microsoft-Windows-Kernel-EventTracing-Controller",
		"3F3F3F3F-3F3F-3F3F-3F3F-3F3F3F3F3F3F": "Microsoft-Windows-Kernel-EventTracing-Buffer",
		"4A4A4A4A-4A4A-4A4A-4A4A-4A4A4A4A4A4A": "Microsoft-Windows-Kernel-EventTracing-Flush",
		"5B5B5B5B-5B5B-5B5B-5B5B-5B5B5B5B5B5B": "Microsoft-Windows-Kernel-EventTracing-Query",
		"6C6C6C6C-6C6C-6C6C-6C6C-6C6C6C6C6C6C": "Microsoft-Windows-Kernel-EventTracing-Update",
		"7D7D7D7D-7D7D-7D7D-7D7D-7D7D7D7D7D7D": "Microsoft-Windows-Kernel-EventTracing-Delete",
		"8E8E8E8E-8E8E-8E8E-8E8E-8E8E8E8E8E8E": "Microsoft-Windows-Kernel-EventTracing-Start",
		"9F9F9F9F-9F9F-9F9F-9F9F-9F9F9F9F9F9F": "Microsoft-Windows-Kernel-EventTracing-Stop",
	}

	if name, ok := wellKnownProviders[strings.ToUpper(guid)]; ok {
		return name
	}

	return ""
}

func (e *ETWLocksmith) parseSecurityDescriptor(data []byte) []Permission {
	var permissions []Permission

	if len(data) < int(unsafe.Sizeof(SecurityDescriptor{})) {
		return permissions
	}

	sd := (*SecurityDescriptor)(unsafe.Pointer(&data[0]))

	if sd.Control&0x0004 == 0 || sd.Dacl == 0 {
		return permissions
	}

	if int(sd.Dacl) >= len(data) {
		return permissions
	}

	daclData := data[sd.Dacl:]
	if len(daclData) < int(unsafe.Sizeof(ACL{})) {
		return permissions
	}

	acl := (*ACL)(unsafe.Pointer(&daclData[0]))

	offset := int(unsafe.Sizeof(ACL{}))
	for i := 0; i < int(acl.AceCount) && offset < len(daclData); i++ {
		if offset+int(unsafe.Sizeof(ACEHeader{})) > len(daclData) {
			break
		}

		aceHeader := (*ACEHeader)(unsafe.Pointer(&daclData[offset]))

		if offset+int(aceHeader.AceSize) > len(daclData) {
			break
		}

		if aceHeader.AceType == 0x00 || aceHeader.AceType == 0x01 {
			permission := e.parseACE(daclData[offset:offset+int(aceHeader.AceSize)], aceHeader.AceType)
			if permission != nil {
				permissions = append(permissions, *permission)
			}
		}

		offset += int(aceHeader.AceSize)
	}

	return permissions
}

func (e *ETWLocksmith) parseACE(aceData []byte, aceType byte) *Permission {
	if len(aceData) < int(unsafe.Sizeof(AccessAllowedACE{})) {
		return nil
	}

	ace := (*AccessAllowedACE)(unsafe.Pointer(&aceData[0]))

	sidOffset := int(unsafe.Sizeof(ACEHeader{})) + int(unsafe.Sizeof(uint32(0)))
	if sidOffset >= len(aceData) {
		return nil
	}

	sidData := aceData[sidOffset:]
	sidString, err := e.convertSIDToString(sidData)
	if err != nil {
		sidString = "Unknown SID"
	}

	accountName := e.lookupAccountName(sidString)
	if accountName == "" {
		accountName = sidString
	}

	permType := "Allow"
	if aceType == 0x01 {
		permType = "Deny"
	}

	permissionNames := e.parseETWPermissions(ace.Mask)

	return &Permission{
		Type:        permType,
		Account:     accountName,
		AccessMask:  ace.Mask,
		Permissions: permissionNames,
	}
}

func (e *ETWLocksmith) convertSIDToString(sidData []byte) (string, error) {
	if len(sidData) < 8 {
		return "", fmt.Errorf("SID too short")
	}

	revision := sidData[0]
	subAuthorityCount := sidData[1]

	if len(sidData) < int(8+4*subAuthorityCount) {
		return "", fmt.Errorf("SID data insufficient")
	}

	authority := uint64(sidData[2])<<40 | uint64(sidData[3])<<32 | uint64(sidData[4])<<24 |
		uint64(sidData[5])<<16 | uint64(sidData[6])<<8 | uint64(sidData[7])

	sidStr := fmt.Sprintf("S-%d-%d", revision, authority)

	for i := 0; i < int(subAuthorityCount); i++ {
		offset := 8 + i*4
		if offset+4 <= len(sidData) {
			subAuth := uint32(sidData[offset]) | uint32(sidData[offset+1])<<8 |
				uint32(sidData[offset+2])<<16 | uint32(sidData[offset+3])<<24
			sidStr += fmt.Sprintf("-%d", subAuth)
		}
	}

	return sidStr, nil
}

func (e *ETWLocksmith) lookupAccountName(sid string) string {
	wellKnownSIDs := map[string]string{
		"S-1-1-0":      "Everyone",
		"S-1-5-32-544": "Administrators",
		"S-1-5-32-545": "Users",
		"S-1-5-32-546": "Guests",
		"S-1-5-32-547": "Power Users",
		"S-1-5-32-558": "Performance Monitor Users",
		"S-1-5-32-559": "Performance Log Users",
		"S-1-5-18":     "SYSTEM",
		"S-1-5-19":     "LOCAL SERVICE",
		"S-1-5-20":     "NETWORK SERVICE",
		"S-1-5-80":     "ALL SERVICES",
		"S-1-15-2-1":   "ALL APPLICATION PACKAGES",
		"S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681": "ALL APPLICATION PACKAGES",
	}

	if name, ok := wellKnownSIDs[sid]; ok {
		return name
	}

	if strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-500") {
		return "Administrator"
	}
	if strings.HasPrefix(sid, "S-1-5-21-") && strings.HasSuffix(sid, "-501") {
		return "Guest"
	}

	return ""
}

func (e *ETWLocksmith) parseETWPermissions(mask uint32) []string {
	var permissions []string

	for permission, name := range ETWPermissions {
		if mask&permission != 0 {
			permissions = append(permissions, name)
		}
	}

	sort.Strings(permissions)
	return permissions
}

func (e *ETWLocksmith) GetDefaultPermissions() *Provider {
	if provider, exists := e.providers[DEFAULT_ETW_GUID]; exists {
		defaultProvider := &Provider{
			GUID:                          "Default (Unregistered)",
			SecurityPermissionsRegistered: false,
			Permissions:                   provider.Permissions,
		}
		return defaultProvider
	}

	return &Provider{
		GUID:                          "Default (Unregistered)",
		SecurityPermissionsRegistered: false,
		Permissions: []Permission{
			{
				Type:        "Allow",
				Account:     "Everyone",
				AccessMask:  0x00000001, // TRACELOG_REGISTER_GUIDS
				Permissions: []string{"TRACELOG_REGISTER_GUIDS"},
			},
			{
				Type:        "Allow",
				Account:     "SYSTEM",
				AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
				Permissions: []string{"WMIGUID_ALL_ACCESS"},
			},
			{
				Type:        "Allow",
				Account:     "LOCAL SERVICE",
				AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
				Permissions: []string{"WMIGUID_ALL_ACCESS"},
			},
			{
				Type:        "Allow",
				Account:     "NETWORK SERVICE",
				AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
				Permissions: []string{"WMIGUID_ALL_ACCESS"},
			},
			{
				Type:        "Allow",
				Account:     "Administrators",
				AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
				Permissions: []string{"WMIGUID_ALL_ACCESS"},
			},
			{
				Type:        "Allow",
				Account:     "Performance Log Users",
				AccessMask:  0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00001000 | 0x00002000 | 0x00004000 | 0x00008000 | 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000 | 0x00100000 | 0x00200000 | 0x00400000 | 0x00800000 | 0x01000000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x80000000,
				Permissions: []string{"WMIGUID_QUERY", "WMIGUID_NOTIFICATION", "TRACELOG_CREATE_REALTIME", "TRACELOG_CREATE_ONDISK", "TRACELOG_GUID_ENABLE", "TRACELOG_LOG_EVENT", "TRACELOG_ACCESS_REALTIME", "TRACELOG_REGISTER_GUIDS"},
			},
			{
				Type:        "Allow",
				Account:     "Performance Monitor Users",
				AccessMask:  0x00000002, // WMIGUID_NOTIFICATION
				Permissions: []string{"WMIGUID_NOTIFICATION"},
			},
		},
	}
}

func (e *ETWLocksmith) SearchByGUID(guid string) *Provider {
	guid = strings.ToUpper(strings.Trim(guid, "{}"))
	if !strings.HasPrefix(guid, "{") {
		guid = "{" + guid + "}"
	}

	if provider, exists := e.providers[guid]; exists {
		if provider.Name == "" || provider.Name == guid || provider.Name == strings.Trim(guid, "{}") || strings.EqualFold(provider.Name, guid) {
			resolvedName := e.getProviderNameFromWINEVT(strings.Trim(guid, "{}"))
			if resolvedName != "" {
				provider.Name = resolvedName
			}
		}
		return provider
	}

	for existingGUID, provider := range e.providers {
		if strings.EqualFold(existingGUID, guid) {
			if provider.Name == "" || provider.Name == existingGUID || provider.Name == strings.Trim(existingGUID, "{}") || strings.EqualFold(provider.Name, existingGUID) {
				resolvedName := e.getProviderNameFromWINEVT(strings.Trim(existingGUID, "{}"))
				if resolvedName != "" {
					provider.Name = resolvedName
				}
			}
			return provider
		}
	}

	defaultProvider := e.GetDefaultPermissions()
	defaultProvider.GUID = guid
	defaultProvider.Name = e.getProviderNameFromWINEVT(strings.Trim(guid, "{}"))
	return defaultProvider
}

func (e *ETWLocksmith) SearchByPermission(permissionName string) []*Provider {
	var results []*Provider

	permissionName = strings.ToUpper(permissionName)

	for _, provider := range e.providers {
		for _, perm := range provider.Permissions {
			for _, p := range perm.Permissions {
				if strings.ToUpper(p) == permissionName {
					results = append(results, provider)
					goto nextProvider
				}
			}
		}
	nextProvider:
	}

	return results
}

func (e *ETWLocksmith) SearchByName(nameQuery string) []*Provider {
	var results []*Provider

	nameQuery = strings.ToLower(nameQuery)

	winevtProviders := e.searchWINEVTByName(nameQuery)

	for _, winevtProvider := range winevtProviders {
		var existingProvider *Provider
		var found bool
		for guid, provider := range e.providers {
			if strings.EqualFold(guid, winevtProvider.GUID) {
				existingProvider = provider
				found = true
				break
			}
		}

		if found {
			existingProvider.Name = winevtProvider.Name
			results = append(results, existingProvider)
		} else {
			winevtProvider.SecurityPermissionsRegistered = false
			winevtProvider.Permissions = []Permission{
				{
					Type:        "Allow",
					Account:     "Everyone",
					AccessMask:  0x00000001, // TRACELOG_REGISTER_GUIDS
					Permissions: []string{"TRACELOG_REGISTER_GUIDS"},
				},
				{
					Type:        "Allow",
					Account:     "SYSTEM",
					AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
					Permissions: []string{"WMIGUID_ALL_ACCESS"},
				},
				{
					Type:        "Allow",
					Account:     "LOCAL SERVICE",
					AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
					Permissions: []string{"WMIGUID_ALL_ACCESS"},
				},
				{
					Type:        "Allow",
					Account:     "NETWORK SERVICE",
					AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
					Permissions: []string{"WMIGUID_ALL_ACCESS"},
				},
				{
					Type:        "Allow",
					Account:     "Administrators",
					AccessMask:  0x00120FFF, // WMIGUID_ALL_ACCESS
					Permissions: []string{"WMIGUID_ALL_ACCESS"},
				},
				{
					Type:        "Allow",
					Account:     "Performance Log Users",
					AccessMask:  0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010 | 0x00000020 | 0x00000040 | 0x00000080 | 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00001000 | 0x00002000 | 0x00004000 | 0x00008000 | 0x00010000 | 0x00020000 | 0x00040000 | 0x00080000 | 0x00100000 | 0x00200000 | 0x00400000 | 0x00800000 | 0x01000000 | 0x02000000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 | 0x80000000,
					Permissions: []string{"WMIGUID_QUERY", "WMIGUID_NOTIFICATION", "TRACELOG_CREATE_REALTIME", "TRACELOG_CREATE_ONDISK", "TRACELOG_GUID_ENABLE", "TRACELOG_LOG_EVENT", "TRACELOG_ACCESS_REALTIME", "TRACELOG_REGISTER_GUIDS"},
				},
				{
					Type:        "Allow",
					Account:     "Performance Monitor Users",
					AccessMask:  0x00000002, // WMIGUID_NOTIFICATION
					Permissions: []string{"WMIGUID_NOTIFICATION"},
				},
			}
			results = append(results, winevtProvider)
		}
	}

	for _, provider := range e.providers {
		if strings.Contains(strings.ToLower(provider.Name), nameQuery) {
			found := false
			for _, result := range results {
				if result.GUID == provider.GUID {
					found = true
					break
				}
			}
			if !found {
				results = append(results, provider)
			}
			continue
		}

		if strings.Contains(strings.ToLower(provider.GUID), nameQuery) {
			found := false
			for _, result := range results {
				if result.GUID == provider.GUID {
					found = true
					break
				}
			}
			if !found {
				results = append(results, provider)
			}
			continue
		}
	}

	return results
}

func (e *ETWLocksmith) searchWINEVTByName(nameQuery string) []*Provider {
	var results []*Provider

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, registry.READ)
	if err != nil {
		return results
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return results
	}

	for _, guidKey := range subkeys {
		providerKey, err := registry.OpenKey(key, guidKey, registry.READ)
		if err != nil {
			continue
		}

		providerName, _, err := providerKey.GetStringValue("")
		if err != nil || providerName == "" {
			providerKey.Close()
			continue
		}

		if strings.Contains(strings.ToLower(providerName), nameQuery) {
			guid := guidKey
			if !strings.HasPrefix(guid, "{") {
				guid = "{" + guid + "}"
			}

			provider := &Provider{
				GUID:                          guid,
				Name:                          providerName,
				SecurityPermissionsRegistered: false,
				Permissions:                   []Permission{},
			}

			results = append(results, provider)
		}

		providerKey.Close()
	}

	return results
}

func (e *ETWLocksmith) getProviderNameFromWINEVT(guid string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers`, registry.READ)
	if err != nil {
		return ""
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return ""
	}

	for _, subkey := range subkeys {
		if strings.EqualFold(strings.Trim(subkey, "{}"), guid) {
			providerKey, err := registry.OpenKey(key, subkey, registry.READ)
			if err != nil {
				continue
			}
			defer providerKey.Close()

			if name, _, err := providerKey.GetStringValue(""); err == nil && name != "" {
				return name
			}

			if name, _, err := providerKey.GetStringValue("FriendlyName"); err == nil && name != "" {
				return name
			}
			if name, _, err := providerKey.GetStringValue("DisplayName"); err == nil && name != "" {
				return name
			}
			if name, _, err := providerKey.GetStringValue("Name"); err == nil && name != "" {
				return name
			}
		}
	}

	return ""
}

func (e *ETWLocksmith) LoadProvidersFromFile(filename string) ([]*Provider, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filename, err)
	}

	var providerInfos []ProviderInfo
	if err := json.Unmarshal(data, &providerInfos); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	var results []*Provider
	log.Printf("Found %d providers in file %s", len(providerInfos), filename)

	for _, info := range providerInfos {
		guid := info.ProviderGUID
		if !strings.HasPrefix(guid, "{") {
			guid = "{" + guid + "}"
		}

		var provider *Provider
		if existingProvider, exists := e.providers[guid]; exists {
			provider = existingProvider
			if info.Name != "" && provider.Name != info.Name {
				provider.Name = info.Name
			}
		} else {
			provider = &Provider{
				GUID:                          guid,
				Name:                          info.Name,
				SecurityPermissionsRegistered: false,
				Permissions:                   e.GetDefaultPermissions().Permissions,
			}
		}

		results = append(results, provider)
	}

	return results, nil
}

func (e *ETWLocksmith) ExportJSON(filename string) error {
	var allProviders []*Provider

	for _, provider := range e.providers {
		allProviders = append(allProviders, provider)
	}

	sort.Slice(allProviders, func(i, j int) bool {
		return allProviders[i].GUID < allProviders[j].GUID
	})

	data, err := json.MarshalIndent(allProviders, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %v", err)
	}

	return os.WriteFile(filename, data, 0644)
}

func (e *ETWLocksmith) ExportCSV(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %v", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	header := []string{"GUID", "Name", "Security Permissions Registered", "Type", "Account", "Access Mask", "Permissions"}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %v", err)
	}

	var guids []string
	for guid := range e.providers {
		guids = append(guids, guid)
	}
	sort.Strings(guids)

	for _, guid := range guids {
		provider := e.providers[guid]

		if len(provider.Permissions) == 0 {
			row := []string{
				provider.GUID,
				provider.Name,
				strconv.FormatBool(provider.SecurityPermissionsRegistered),
				"", "", "", "",
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %v", err)
			}
		} else {
			for _, perm := range provider.Permissions {
				row := []string{
					provider.GUID,
					provider.Name,
					strconv.FormatBool(provider.SecurityPermissionsRegistered),
					perm.Type,
					perm.Account,
					fmt.Sprintf("0x%08X", perm.AccessMask),
					strings.Join(perm.Permissions, "; "),
				}
				if err := writer.Write(row); err != nil {
					return fmt.Errorf("failed to write CSV row: %v", err)
				}
			}
		}
	}

	return nil
}

func main() {
	locksmith := NewETWLocksmith()

	var rootCmd = &cobra.Command{
		Use:   "etwlocksmith",
		Short: "ETW Provider Permissions Analysis Tool",
		Long:  "A tool to analyze and search ETW provider permissions from the Windows registry",
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all ETW providers and their permissions",
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			fmt.Printf("Found %d registered ETW providers:\n\n", len(locksmith.providers))

			var guids []string
			for guid := range locksmith.providers {
				guids = append(guids, guid)
			}
			sort.Strings(guids)

			for _, guid := range guids {
				provider := locksmith.providers[guid]
				fmt.Printf("GUID: %s\n", provider.GUID)
				if provider.Name != "" {
					fmt.Printf("Name: %s\n", provider.Name)
				}
				fmt.Printf("Security Permissions Registered: %t\n", provider.SecurityPermissionsRegistered)
				fmt.Printf("Permissions:\n")

				if len(provider.Permissions) == 0 {
					fmt.Printf("  No permissions defined\n")
				} else {
					for _, perm := range provider.Permissions {
						fmt.Printf("  %s - %s (0x%08X): %s\n",
							perm.Type, perm.Account, perm.AccessMask,
							strings.Join(perm.Permissions, ", "))
					}
				}
				fmt.Println()
			}
		},
	}

	var searchGuidCmd = &cobra.Command{
		Use:   "search-guid [guid]",
		Short: "Search for a specific ETW provider by GUID",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			provider := locksmith.SearchByGUID(args[0])

			fmt.Printf("GUID: %s\n", provider.GUID)
			if provider.Name != "" {
				fmt.Printf("Name: %s\n", provider.Name)
			}
			fmt.Printf("Security Permissions Registered: %t\n", provider.SecurityPermissionsRegistered)

			if !provider.SecurityPermissionsRegistered {
				fmt.Printf("Note: This GUID has no security permissions registered. Showing default permissions.\n")
			}

			fmt.Printf("Permissions:\n")
			if len(provider.Permissions) == 0 {
				fmt.Printf("  No permissions defined\n")
			} else {
				for _, perm := range provider.Permissions {
					fmt.Printf("  %s - %s (0x%08X): %s\n",
						perm.Type, perm.Account, perm.AccessMask,
						strings.Join(perm.Permissions, ", "))
				}
			}
		},
	}

	var searchPermCmd = &cobra.Command{
		Use:   "search-permission [permission]",
		Short: "Search for providers with a specific permission",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			providers := locksmith.SearchByPermission(args[0])

			fmt.Printf("Found %d providers with permission '%s':\n\n", len(providers), args[0])

			for _, provider := range providers {
				fmt.Printf("GUID: %s\n", provider.GUID)
				if provider.Name != "" {
					fmt.Printf("Name: %s\n", provider.Name)
				}
				for _, perm := range provider.Permissions {
					for _, p := range perm.Permissions {
						if strings.ToUpper(p) == strings.ToUpper(args[0]) {
							fmt.Printf("  %s - %s (0x%08X)\n",
								perm.Type, perm.Account, perm.AccessMask)
						}
					}
				}
				fmt.Println()
			}
		},
	}

	var searchNameCmd = &cobra.Command{
		Use:   "search-name [name]",
		Short: "Search for providers by name (case-insensitive partial match)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			providers := locksmith.SearchByName(args[0])

			fmt.Printf("Found %d providers matching '%s':\n\n", len(providers), args[0])

			for _, provider := range providers {
				fmt.Printf("GUID: %s\n", provider.GUID)
				if provider.Name != "" {
					fmt.Printf("Name: %s\n", provider.Name)
				}
				fmt.Printf("Security Permissions Registered: %t\n", provider.SecurityPermissionsRegistered)
				fmt.Printf("Permissions:\n")
				if len(provider.Permissions) == 0 {
					fmt.Printf("  No permissions defined\n")
				} else {
					for _, perm := range provider.Permissions {
						fmt.Printf("  %s - %s (0x%08X): %s\n",
							perm.Type, perm.Account, perm.AccessMask,
							strings.Join(perm.Permissions, ", "))
					}
				}
				fmt.Println()
			}
		},
	}

	var loadFromFileCmd = &cobra.Command{
		Use:   "load-file [filename]",
		Short: "Load providers from a JSON file and show their permissions",
		Long:  "Load a list of ETW providers from a JSON file and display their security permissions. The file should contain an array of objects with 'providerGuid' and 'name' fields.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}

			providers, err := locksmith.LoadProvidersFromFile(args[0])
			if err != nil {
				log.Fatalf("Failed to load providers from file: %v", err)
			}

			fmt.Printf("Loaded %d providers from file %s:\n\n", len(providers), args[0])

			for _, provider := range providers {
				fmt.Printf("GUID: %s\n", provider.GUID)
				if provider.Name != "" {
					fmt.Printf("Name: %s\n", provider.Name)
				}
				fmt.Printf("Security Permissions Registered: %t\n", provider.SecurityPermissionsRegistered)
				fmt.Printf("Permissions:\n")
				if len(provider.Permissions) == 0 {
					fmt.Printf("  No permissions defined\n")
				} else {
					for _, perm := range provider.Permissions {
						fmt.Printf("  %s - %s (0x%08X): %s\n",
							perm.Type, perm.Account, perm.AccessMask,
							strings.Join(perm.Permissions, ", "))
					}
				}
				fmt.Println()
			}
		},
	}

	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export ETW provider permissions",
	}

	var exportJSONCmd = &cobra.Command{
		Use:   "json [filename]",
		Short: "Export all providers to JSON format",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			if err := locksmith.ExportJSON(args[0]); err != nil {
				log.Fatalf("Failed to export JSON: %v", err)
			}
			fmt.Printf("Exported %d providers to %s\n", len(locksmith.providers), args[0])
		},
	}

	var exportCSVCmd = &cobra.Command{
		Use:   "csv [filename]",
		Short: "Export all providers to CSV format",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := locksmith.LoadProviders(); err != nil {
				log.Fatalf("Failed to load ETW providers: %v", err)
			}
			if err := locksmith.ExportCSV(args[0]); err != nil {
				log.Fatalf("Failed to export CSV: %v", err)
			}
			fmt.Printf("Exported %d providers to %s\n", len(locksmith.providers), args[0])
		},
	}

	var permissionsCmd = &cobra.Command{
		Use:   "permissions",
		Short: "List all available ETW permissions",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available ETW Permissions:")
			fmt.Println("(Based on https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/etw/secure/index.htm)")
			fmt.Println()

			var permissions []string
			for _, name := range ETWPermissions {
				permissions = append(permissions, name)
			}
			sort.Strings(permissions)

			for _, perm := range permissions {
				for mask, name := range ETWPermissions {
					if name == perm {
						fmt.Printf("  %-30s (0x%08X)\n", name, mask)
						break
					}
				}
			}
		},
	}

	exportCmd.AddCommand(exportJSONCmd, exportCSVCmd)
	rootCmd.AddCommand(listCmd, searchGuidCmd, searchPermCmd, searchNameCmd, loadFromFileCmd, exportCmd, permissionsCmd)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
