// Copyright 2025 Cyprob Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");

package plugin

import "slices"

// Category represents a plugin category for organization and filtering.
type Category string

// Standard plugin categories.
const (
	CategorySSH      Category = "ssh"
	CategoryHTTP     Category = "http"
	CategoryWeb      Category = "web"
	CategoryTLS      Category = "tls"
	CategoryDatabase Category = "database"
	CategoryIoT      Category = "iot"
	CategoryNetwork  Category = "network"
	CategoryMisc     Category = "misc"
)

// AllCategories returns all defined categories.
func AllCategories() []Category {
	return []Category{
		CategorySSH,
		CategoryHTTP,
		CategoryWeb,
		CategoryTLS,
		CategoryDatabase,
		CategoryIoT,
		CategoryNetwork,
		CategoryMisc,
	}
}

// String returns the string representation of the category.
func (c Category) String() string {
	return string(c)
}

// IsValid checks if the category is a valid standard category.
func (c Category) IsValid() bool {
	return slices.Contains(AllCategories(), c)
}

// CategoryFromString converts a string to a Category.
// Returns CategoryMisc if the string doesn't match any known category.
func CategoryFromString(s string) Category {
	cat := Category(s)
	if cat.IsValid() {
		return cat
	}
	return CategoryMisc
}

// PortToCategories maps common ports to their likely categories.
func PortToCategories(port int) []Category {
	switch port {
	case 22:
		return []Category{CategorySSH}
	case 80, 8080, 8000, 8888:
		return []Category{CategoryHTTP, CategoryWeb}
	case 443, 8443:
		return []Category{CategoryHTTP, CategoryWeb, CategoryTLS}
	case 21:
		return []Category{CategoryNetwork}
	case 3306:
		return []Category{CategoryDatabase} // MySQL
	case 5432:
		return []Category{CategoryDatabase} // PostgreSQL
	case 27017:
		return []Category{CategoryDatabase} // MongoDB
	case 6379:
		return []Category{CategoryDatabase} // Redis
	case 1883, 8883:
		return []Category{CategoryIoT} // MQTT
	default:
		return []Category{CategoryMisc}
	}
}

// ServiceToCategories maps service names to their categories.
func ServiceToCategories(service string) []Category {
	switch service {
	case "ssh", "openssh":
		return []Category{CategorySSH}
	case "http", "https", "http-alt":
		return []Category{CategoryHTTP, CategoryWeb}
	case "tls", "ssl":
		return []Category{CategoryTLS}
	case "mysql", "postgresql", "postgres", "mongodb", "redis":
		return []Category{CategoryDatabase}
	case "mqtt", "coap":
		return []Category{CategoryIoT}
	case "ftp", "telnet", "smtp", "dns":
		return []Category{CategoryNetwork}
	default:
		return []Category{CategoryMisc}
	}
}
