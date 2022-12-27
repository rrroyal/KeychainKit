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

	let accessGroup: String

	private let baseQuery: QueryDictionary
	private let textEncoding: String.Encoding = .utf8

	private let _kSecAttrDescription = "Harbour - Token"
	private let _kSecClass = kSecClassGenericPassword

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
			// kSecClass: kSecClassInternetPassword
			kSecClass: _kSecClass
//			kSecAttrService: service
		]
	}

	// MARK: - Public functions

	/// Stores provided content in keychain under specified service URL.
	/// - Parameters:
	///   - content: Content to store
	///   - server: Service URL
	public func saveContent(_ content: String, for url: URL) throws {
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
			kSecAttrDescription: _kSecAttrDescription
		]

		try addOrUpdate(query: query, attributes: attributes)
	}

	/// Retrieves content for specified service URL..
	/// - Parameter server: Service URL
	/// - Returns: Saved content
	public func getContent(for url: URL) throws -> String {
		var query = baseQuery
		// query[kSecAttrServer] = url.absoluteString
		query[kSecAttrService] = url.absoluteString
		query[kSecMatchLimit] = kSecMatchLimitOne
		query[kSecReturnData] = true

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
	/// - Parameter server: Service URL
	public func removeContent(for url: URL) throws {
		var query = baseQuery
		// query[kSecAttrServer] = url.absoluteString
		query[kSecAttrService] = url.absoluteString
		let status = SecItemDelete(query as CFDictionary)
		guard status == errSecSuccess || status == errSecItemNotFound else { throw SecError(status) }
	}

	/// Returns all saved URLs.
	/// - Returns: Array of URLs
	public func getSavedURLs() throws -> [URL] {
		var query = baseQuery
//		query[kSecAttrDescription] = Self.tokenItemDescription
		query[kSecMatchLimit] = kSecMatchLimitAll
		query[kSecReturnAttributes] = true
		query[kSecReturnData] = false

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
}
