//
//  Keychain+Errors.swift
//  Keychain
//
//  Created by royal on 10/06/2021.
//

import Foundation

// MARK: - Keychain+KeychainError

public extension Keychain {
	enum KeychainError: Error, Sendable {
		case encodingFailed
		case decodingFailed
	}
}

// MARK: - Keychain+SecError

public extension Keychain {
	struct SecError: LocalizedError, Sendable {
		public let status: OSStatus

		public var errorDescription: String? {
			"\(SecCopyErrorMessageString(status, nil) as String? ?? "Unknown error") (\(self.status))"
		}

		internal init(_ status: OSStatus) {
			self.status = status
		}
	}
}
