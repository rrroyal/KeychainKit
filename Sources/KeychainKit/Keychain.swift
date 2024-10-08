//
//  Keychain.swift
//  Keychain
//
//  Created by royal on 10/06/2021.
//

import Foundation
import Security

public final class Keychain: Sendable {
	private typealias QueryDictionary = [String: Any]

	public static let defaultItemClass = kSecClassGenericPassword as String
	//	public static let defaultStringEncoding: String.Encoding = .utf8

	public let accessGroup: String
	// public var applicationTagPrefix: String?

	private nonisolated(unsafe) let baseQuery: QueryDictionary

	// MARK: - init

	/// Initializes Keychain with supplied configuration.
	/// - Parameters:
	///   - accessGroup: Access group (i.e. app group)
	public init(accessGroup: String) {
		self.accessGroup = accessGroup

		self.baseQuery = [
			kSecAttrAccessGroup as String: accessGroup,
			kSecAttrSynchronizable as String: true,
			kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
		]
	}

	// MARK: - Public

	// MARK: Save*

	/// Stores provided data in the keychain under specified key.
	/// - Parameters:
	///   - data: Data to store
	///   - key: Item key
	///   - itemDescription: Keychain item description
	///   - itemClass: Keychain item class
	public func setData(
		_ data: Data,
		for key: String,
		itemDescription: String? = nil,
		itemClass: String = Keychain.defaultItemClass
	) throws {
		var query = baseQuery
		query[kSecClass as String] = itemClass
		query[kSecAttrService as String] = key
		query[kSecAttrLabel as String] = key
		query[kSecAttrDescription as String] = itemDescription

		let attributes: QueryDictionary = [
			kSecValueData as String: data,
//			kSecAttrLabel: key,
		]

		try addOrUpdate(query: query, attributes: attributes)
	}

	/// Stores provided string in the keychain under specified key.
	/// - Parameters:
	///   - string: String to store
	///   - key: Item key
	///   - itemDescription: Keychain item description
	///   - itemClass: Keychain item class
	@inlinable
	public func setString(
		_ string: String,
		for key: String,
		itemDescription: String? = nil,
		itemClass: String = Keychain.defaultItemClass
	) throws {
		guard let data = string.data(using: .utf8) else {
			throw KeychainError.encodingFailed
		}
		try setData(data, for: key, itemDescription: itemDescription, itemClass: itemClass)
	}

	// MARK: Get*

	/// Retrieves data for specified item key.
	/// - Parameters:
	///   - key: Item key
	///   - itemClass: Keychain item class
	/// - Returns: Saved data
	public func getData(for key: String, itemClass: String = Keychain.defaultItemClass) throws -> Data {
		var query = baseQuery
		query[kSecClass as String] = itemClass
		query[kSecAttrService as String] = key
//		query[kSecAttrLabel as String] = key
		query[kSecMatchLimit as String] = kSecMatchLimitOne
		query[kSecReturnData as String] = true

		var _data: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &_data)
		guard status == errSecSuccess else {
			throw SecError(status)
		}

		guard let data = _data as? Data else {
			throw KeychainError.decodingFailed
		}

		return data
	}

	/// Retrieves data for specified item key.
	/// - Parameters:
	///   - key: Item key
	///   - itemClass: Keychain item class
	/// - Returns: Saved string
	@inlinable
	public func getString(for key: String, itemClass: String = Keychain.defaultItemClass) throws -> String {
		let data = try getData(for: key, itemClass: itemClass)
		guard let string = String(data: data, encoding: .utf8) else {
			throw KeychainError.decodingFailed
		}
		return string
	}

	/// Deletes content for supplied service URL.
	/// - Parameters:
	///   - url: Item key
	///   - itemClass: Keychain item class
	public func removeContent(for key: String, itemClass: String = Keychain.defaultItemClass) throws {
		var query = baseQuery
//		query[kSecAttrServer as String] = url.absoluteString
		query[kSecAttrService as String] = key
//		query[kSecAttrApplicationTag as String] = applicationTag(for: url)
		query[kSecClass as String] = itemClass

		let status = SecItemDelete(query as CFDictionary)
		guard status == errSecSuccess || status == errSecItemNotFound else { throw SecError(status) }
	}

	/// Returns all saved URLs.
	/// - Parameter itemClass: Keychain item class
	/// - Returns: Array of URLs
	public func getSavedURLs(itemClass: String = Keychain.defaultItemClass) throws -> [URL] {
		var query = baseQuery
		query[kSecMatchLimit as String] = kSecMatchLimitAll
		query[kSecReturnAttributes as String] = true
		query[kSecReturnData as String] = false
		query[kSecClass as String] = itemClass

		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		guard status == errSecSuccess else {
			throw SecError(status)
		}

		guard let dict = item as? [[String: Any]] else {
			throw KeychainError.decodingFailed
		}

		let urls: [URL] = dict.compactMap {
			guard let string = $0[kSecAttrService as String] as? String else { return nil }
			return URL(string: string)
		}

		return urls
	}
}

// MARK: - Keychain+Private

private extension Keychain {
	/// Adds or updates item with supplied query and attributes,
	/// - Parameters:
	///   - query: Item query
	///   - attributes: Item attributes
	private func addOrUpdate(query: QueryDictionary, attributes: QueryDictionary) throws {
		let addQuery = query.merging(attributes, uniquingKeysWith: { $1 })
		let addStatus = SecItemAdd(addQuery as CFDictionary, nil)

		switch addStatus {
		case errSecSuccess:
			return
		case errSecDuplicateItem:
			let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
			guard updateStatus == errSecSuccess else {
				throw SecError(updateStatus)
			}
		default:
			throw SecError(addStatus)
		}
	}
}
