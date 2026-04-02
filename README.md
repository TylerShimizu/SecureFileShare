# Project 2 — Secure FileShare (Design + Implementation)

This repository is a design + implementation project: you will design and implement a secure file-sharing system from scratch that defends against a strong Datastore adversary. Read the full project spec for details: https://cs161.org/proj2/.

Goals
- Implement a secure, stateless file store that supports storing, loading, appending, sharing, accepting invitations, and revocation.
- Ensure confidentiality and integrity of stored data despite an attacker who can read and modify Datastore.
- Design appropriate on-disk (Datastore) structures and use Keystore for public keys only.

Functionality (the 8 required functions)
- InitUser(username, password) -> create a new user
- GetUser(username, password) -> login and return a fresh User object
- (User).StoreFile(filename, contents) -> create/overwrite a file
- (User).LoadFile(filename) -> fetch file contents
- (User).AppendToFile(filename, contents) -> append efficiently
- (User).CreateInvitation(filename, targetUser) -> produce invitation UUID
- (User).AcceptInvitation(invitationUUID, newFilename) -> accept a share under local filename
- (User).RevokeAccess(filename, targetUser) -> revoke a previously granted access

User objects and constructors
- InitUser and GetUser are constructors that return a *User (a Go memory pointer to a User struct).
- Each device/login gets a fresh User object — the implementation must not rely on global in-memory state for persistence.
- All persistent state must be stored on Datastore and Keystore.

Design constraints / assumptions
- Atomic operations: no concurrent calls; attackers act only between function calls.
- Stateless design: do not rely on globals or local persistent memory; all persistent info must go to Datastore or Keystore.
- Keystore: name-value pairs where the value must be a public key (PKEEncKey or DSVerifyKey). Values are immutable once written. Each user may only publish a small, constant number of public keys.
- Datastore: name-value pairs keyed by UUID (unique 16-byte strings). Values are arbitrary byte arrays. Datastore is fully readable and writable by the Datastore adversary.

Threat model (Datastore Adversary)
- The adversary can read, write, add, and list any Datastore entries at any time (but not during a function call).
- The adversary has a copy of your source code and can mimic it.
- The adversary will not perform rollback attacks on individual UUIDs or multiple UUIDs.
- There is also a Revoked User adversary (described in the spec) who may try to access files after revocation; design must prevent revoked users from accessing content they should no longer see.

When designing these structs, specify for each: where it lives (Datastore vs Keystore), how you derive its UUID, what keys protect it, and how integrity is validated.

Error handling
- All API functions return an error. On success return nil.
- If tampering or invalid inputs are detected, return a non-nil error.
- Do not panic. Any detected corruption must be signaled via an error.
- After returning a non-nil error, subsequent calls may have undefined behavior (but must still not leak confidential data).

Testing
- Unit test helpers in client/client_unittest.go.
- Integration tests in client_test/client_test.go.
- Test scenarios should include normal usage, sharing/accepting, revocation, and adversarial tampering of Datastore entries (tests in the spec and autograder will do this).

Notes
- This is fundamentally a design project: document your on-Datastore/Keystore data formats and the cryptographic keys used to protect them.
- Keep the implementation stateless and robust to an active Datastore adversary.

Good luck — design carefully and test thoroughly