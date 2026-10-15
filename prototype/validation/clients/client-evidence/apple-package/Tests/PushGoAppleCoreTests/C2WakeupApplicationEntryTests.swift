import Foundation
import Testing
@testable import PushGoAppleCore

/// Run ingest and recover in separate swift test processes using the same storage root.
/// Enters the unchanged application ingress controller with captured provider wakeup bytes.
@MainActor
struct C2WakeupApplicationEntryTests {
    private func env(_ key: String) throws -> String {
        try #require(ProcessInfo.processInfo.environment[key], "Missing \(key)")
    }

    @Test
    func capturedWakeupThroughApplicationControllerAndProcessRestart() async throws {
        let phase = try env("C2_PHASE")
        #expect(phase == "ingest" || phase == "recover")
        let root = URL(fileURLWithPath: try env("C2_EVIDENCE_DIR"), isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let base = try #require(URL(string: env("C2_GATEWAY_URL")))
        let device = try env("C2_DEVICE_KEY")
        let delivery = try env("C2_DELIVERY_ID")
        let title = try env("C2_EXPECTED_TITLE")
        let body = try env("C2_EXPECTED_BODY")
        let storageRoot = try #require(PushGoAutomationContext.storageRootURL)
        try #require(storageRoot.standardizedFileURL == root.appendingPathComponent("native-store", isDirectory: true).standardizedFileURL)
        // Keep singleton claim/journal ownership identical to the production app.
        // The fresh automation storage root isolates the real app group name.
        let group = AppConstants.appGroupIdentifier
        let capture = try Data(contentsOf: URL(fileURLWithPath: env("C2_CAPTURED_WAKEUP_PATH")))
        let payload = try #require(JSONSerialization.jsonObject(with: capture) as? [String: Any])
        #expect(NotificationHandling.providerWakeupPullDeliveryId(from: payload) == delivery)
        let codablePayload = payload.mapValues(AnyCodable.init)
        let store = LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil)
        let inbox = NotificationIngressInbox(appGroupIdentifier: group)
        let markers = ProviderDeliveryAckFailureStore(appGroupIdentifier: group)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        var errors: [String] = []
        let controller = NotificationIngressController(
            platformSuffix: "macos", dataStore: store,
            channelSubscriptionService: ChannelSubscriptionService(session: session),
            serverConfigProvider: { ServerConfig(baseURL: base, token: nil) },
            cachedDeviceKeyProvider: { device }, beforePersistMessage: { _ in },
            scheduleCountsRefresh: {}, recordProviderError: { error, source in
                errors.append("\(source): \(error)")
            }, shouldDeferStartupWakeupPulls: { false },
            notificationIngressInbox: inbox, ackFailureStore: markers
        )
        if phase == "ingest" {
            #expect(try await store.loadMessages().isEmpty)
            _ = await store.saveCachedDeviceKey(device, for: "macos")
            let enqueued = await inbox.enqueue(codablePayload: codablePayload, requestIdentifier: delivery, source: "c2.captured_provider_wakeup", ackIdentity: nil, requiredEntryState: "durable")
            #expect(enqueued)
            let outcome = await controller.mergeNotificationIngressInboxOutcome(reason: "c2_actual_wakeup", allowWakeupSync: true)
            #expect(outcome.appliedCount == 1)
            // This waits for the controller's own scheduled ACK task. The fixture
            // deliberately returns a failed ACK while retaining its target.
            #expect(await controller.drainProviderDeliveryAckFailures(source: "c2.ingest") == .failed)
            let rows = try await store.loadMessages(deliveryId: delivery)
            #expect(rows.count == 1)
            #expect(rows.first?.title == title)
            #expect(rows.first?.body == body)
            let pending = await markers.pendingMarkers(limit: 10, now: Date().addingTimeInterval(120))
            #expect(pending.count == 1)
            #expect(pending.first?.identity?.deliveryId == delivery)
            #expect(pending.first?.identity?.deviceKey == device)
            #expect(pending.first?.identity?.baseURL == base)
            #expect((pending.first?.attemptCount ?? 0) > 0)
            #expect(!errors.isEmpty)
        } else {
            // The process has not re-enqueued or directly synchronized anything.
            // Both content and failed ACK must be present before recovery starts.
            let before = try await store.loadMessages(deliveryId: delivery)
            #expect(before.count == 1)
            #expect(before.first?.title == title)
            #expect(before.first?.body == body)
            let durable = await markers.pendingMarkers(limit: 10, now: Date().addingTimeInterval(120))
            #expect(durable.count == 1)
            #expect((durable.first?.attemptCount ?? 0) > 0)
            // Honor the production backoff; no clock override, marker mutation,
            // SQL rewrite, or synthetic retry row is used.
            if let due = await markers.nextAttemptDate() {
                let remaining = due.timeIntervalSinceNow
                #expect(remaining < 65)
                if remaining > 0 { try await Task.sleep(for: .seconds(remaining + 0.1)) }
            }
            #expect(await controller.drainProviderDeliveryAckFailures(source: "c2.fresh_process_recovery") == .succeeded)
            #expect(await markers.pendingMarkers(limit: 10, now: Date().addingTimeInterval(120)).isEmpty)
            // Recreate the repositories after ACK and check exact content remains.
            let reopened = LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil)
            let after = try await reopened.loadMessages(deliveryId: delivery)
            #expect(after.count == 1)
            #expect(after.first?.id == before.first?.id)
            #expect(after.first?.title == title)
            #expect(after.first?.body == body)
            #expect(errors.isEmpty)
        }
        let receipt: [String: Any] = [
            "phase": phase, "process_id": ProcessInfo.processInfo.processIdentifier,
            "entry": "NotificationIngressController.mergeNotificationIngressInboxOutcome",
            "delivery_id": delivery, "canonical_count": try await store.loadMessages(deliveryId: delivery).count,
            "provider_errors": errors,
            "scope": "macOS host application controller + unchanged GRDB persistence and durable ACK; no APNs or delegate OS dispatch"
        ]
        try JSONSerialization.data(withJSONObject: receipt, options: [.prettyPrinted, .sortedKeys])
            .write(to: root.appendingPathComponent("apple-\(phase)-observations.json"))
    }
}
