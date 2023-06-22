//
//  Keychain.swift
//  Keychain
//
//  Created by royal on 10/06/2021.
//

import Foundation
import Security

public final class Keychain {
	private typealias QueryDictionary = [CFString: Any]
	
	public static let defaultItemClass = kSecClassGenericPassword as String

	public let accessGroup: String
	// public var applicationTagPrefix: String?

	private let baseQuery: QueryDictionary
	private let textEncoding: String.Encoding = .utf8

	// MARK: - init

	/// Initializes Keychain with supplied configuration.
	/// - Parameters:
	///   - accessGroup: Access group (i.e. app group)
	public init(accessGroup: String) {
		self.accessGroup = accessGroup

		self.baseQuery = [
			kSecAttrAccessGroup: accessGroup,
			kSecAttrSynchronizable: true,
			kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
		]
	}

	// MARK: - Public functions

	/// Stores provided content in keychain under specified service URL.
	/// - Parameters:
	///   - content: Content to store
	///   - url: Service URL
	///   - itemDescription: Keychain item description
	///   - itemClass: Keychain item class
	public func saveContent(_ content: String,
							for url: URL,
							itemDescription: String? = nil,
							itemClass: String = kSecClassGenericPassword as String) throws {
		var query = baseQuery
		// query[kSecAttrServer] = url.absoluteString
		query[kSecAttrService] = url.absoluteString

		guard let tokenData = content.data(using: self.textEncoding) else {
			throw KeychainError.encodingFailed
		}
		let attributes: QueryDictionary = [
			kSecValueData: tokenData,
			// kSecAttrComment: comment as Any,
			// kSecAttrPath: url.path,
			kSecAttrLabel: url.absoluteString,
			kSecAttrDescription: itemDescription as Any,
			kSecClass: itemClass,
			// kSecAttrApplicationTag: applicationTag(for: url)
		]

		try addOrUpdate(query: query, attributes: attributes)
	}

	/// Retrieves content for specified service URL..
	/// - Parameters:
	///   - url: Service URL
	///   - itemClass: Keychain item class
	/// - Returns: Saved content
	public func getContent(for url: URL, itemClass: String = Keychain.defaultItemClass) throws -> String {
		var query = baseQuery
		// query[kSecAttrServer] = url.absoluteString
		query[kSecAttrService] = url.absoluteString
		query[kSecMatchLimit] = kSecMatchLimitOne
		query[kSecReturnData] = true
		query[kSecClass] = itemClass

		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		guard status == errSecSuccess else {
			throw SecError(status)
		}

		guard let data = item as? Data,
			  let password = String(data: data, encoding: self.textEncoding) else {
			throw KeychainError.decodingFailed
		}

		return password
	}

	/// Deletes content for supplied service URL.
	/// - Parameters:
	///   - url: Service URL
	///   - itemClass: Keychain item class
	public func removeContent(for url: URL, itemClass: String = Keychain.defaultItemClass) throws {
		var query = baseQuery
		// query[kSecAttrServer] = url.absoluteString
		query[kSecAttrService] = url.absoluteString
		// query[kSecAttrApplicationTag] = applicationTag(for: url)
		query[kSecClass] = itemClass

		let status = SecItemDelete(query as CFDictionary)
		guard status == errSecSuccess || status == errSecItemNotFound else { throw SecError(status) }
	}

	/// Returns all saved URLs.
	/// - Parameter itemClass: Keychain item class
	/// - Returns: Array of URLs
	public func getSavedURLs(itemClass: String = Keychain.defaultItemClass) throws -> [URL] {
		var query = baseQuery
		query[kSecMatchLimit] = kSecMatchLimitAll
		query[kSecReturnAttributes] = true
		query[kSecReturnData] = false
		query[kSecClass] = itemClass

		var item: CFTypeRef?
		let status = SecItemCopyMatching(query as CFDictionary, &item)
		guard status == errSecSuccess else {
			throw SecError(status)
		}

		guard let dict = item as? [[String: Any]] else {
			throw KeychainError.decodingFailed
		}

		let urls: [URL] = dict.compactMap {
			guard let string = $0[kSecAttrLabel as String] as? String else { return nil }
			return URL(string: string)
		}

		return urls
	}

	// MARK: - Helpers

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
	
	/*
	/// Generates item tag for specified URL.
	/// - Parameter url: Item service URL
	/// - Returns: Item tag
	private func applicationTag(for url: URL) -> String {
		if let applicationTagPrefix {
			return "\(applicationTagPrefix).\(url.absoluteString)"
		}
		return url.absoluteString
	}
	*/
}
