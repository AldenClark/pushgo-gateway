import Foundation
import Testing
@testable import PushGoAppleCore

/// Real application controllers and repositories, local synthetic provider only.
/// Each invocation is a fresh native process; all storage is isolated on disk.
@MainActor
struct C3OrdinaryClientLoopTests {
    private func env(_ key: String) throws -> String {
        try #require(ProcessInfo.processInfo.environment[key], "Missing \(key)")
    }
    private func write(_ object: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]).write(to: url)
    }
    @Test
    func ordinaryClientLoop() async throws {
        let phase = try env("C3_PHASE")
        let root = URL(fileURLWithPath: try env("C3_EVIDENCE_DIR"), isDirectory: true)
        let base = try #require(URL(string: env("C3_GATEWAY_URL")))
        let storage = try #require(PushGoAutomationContext.storageRootURL)
        try #require(storage.standardizedFileURL == root.appendingPathComponent("native-store", isDirectory: true).standardizedFileURL)
        let group = AppConstants.appGroupIdentifier
        let store = LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil)
        let service = ChannelSubscriptionService(session: URLSession(configuration: .ephemeral))
        let config = ServerConfig(baseURL: base, token: nil)
        let localization = LocalizationManager()
        var runtimeErrors: [String] = []
        let route = ProviderRouteController(platform: "macos", dataStore: store, channelSubscriptionService: service,
            localizationManager: localization, refreshAutomationState: {}, runtimeMessageRecorder: { text, source, _, _ in runtimeErrors.append("\(source): \(text)") })
        let registration = PushRegistrationService.testing(automationProviderToken: try env("C3_PROVIDER_TOKEN"), bypassPushAuthorizationPrompt: true)
        let sync = ChannelSyncController(platform: "macos", dataStore: store, pushRegistrationService: registration,
            channelSubscriptionService: service, providerRouteController: route, localizationManager: localization,
            serverConfigProvider: { config }, requestWatchStandaloneProvisioningSync: { _ in },
            recordRuntimeError: { error, source in runtimeErrors.append("\(source): \(error)") }, showToast: { _ in }, showChannelEntryFeedback: { _ in })
        let channels = ChannelSubscriptionController(platform: "macos", dataStore: store, channelSubscriptionService: service,
            providerRouteController: route, channelSyncController: sync, localizationManager: localization, serverConfigProvider: { config })
        var observation: [String: Any] = ["phase": phase, "process_id": ProcessInfo.processInfo.processIdentifier,
            "scope": "unchanged production application controllers, actual local Gateway HTTP and GRDB; synthetic provider token/capture; no OS APNs dispatch"]
        let bootURL = root.appendingPathComponent("bootstrap.json")
        if phase == "bootstrap" {
            // Automation redirects shared preferences to the test executable's
            // standard defaults, which can survive prior independent test runs.
            // Clear those exact production config/device caches through their
            // public owners before establishing this fresh local connection.
            try #require(PushGoAutomationContext.blocksCrossAppDataAccess)
            try #require(AppConstants.sharedUserDefaults() === UserDefaults.standard)
            try await store.saveServerConfig(nil)
            try await route.restoreProviderDeviceKey(nil, source: "c3.isolated_setup")
            #expect(try await store.loadServerConfig() == nil)
            try await store.saveServerConfig(config)
            let reopened = LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil)
            #expect(try await reopened.loadServerConfig()?.baseURL == config.normalized().baseURL)
            let providerToken = try await registration.awaitToken()
            let device = try await route.ensureProviderRoute(config: config, providerToken: providerToken)
            #expect(await reopened.cachedDeviceKey(for: "macos") == device)
            let credential = UUID().uuidString
            let first = try await channels.createChannel(alias: "C3 native ordinary", password: credential)
            #expect(first.created && first.subscribed)
            let repeated = try await channels.subscribeChannel(channelId: first.channelId, password: credential)
            #expect(repeated.subscribed && repeated.channelId == first.channelId)
            try await channels.renameChannel(channelId: first.channelId, alias: "C3 renamed ordinary")
            let second = try await channels.createChannel(alias: "C3 isolation survivor", password: credential)
            try await sync.syncSubscriptionsIfNeeded()
            let persisted = try await reopened.loadChannelSubscriptions(gateway: config.gatewayKey, includeDeleted: false)
            #expect(persisted.count == 2)
            #expect(persisted.first { $0.channelId == first.channelId }?.displayName == "C3 renamed ordinary")
            #expect(persisted.allSatisfy { $0.lastSyncedAt != nil })
            try write(["device_key":device,"channel_id":first.channelId,"survivor_channel_id":second.channelId,"credential":credential],to:bootURL)
            observation["device_key"] = device
            observation["channel_id"] = first.channelId
        } else {
            let boot = try #require(JSONSerialization.jsonObject(with: Data(contentsOf: bootURL)) as? [String:String])
            let device = try #require(boot["device_key"])
            let channel = try #require(boot["channel_id"])
            #expect(try await store.loadServerConfig()?.baseURL == config.normalized().baseURL)
            #expect(await store.cachedDeviceKey(for: "macos") == device)
            if phase == "sync" {
                try await sync.syncSubscriptionsIfNeeded()
                let rows = try await store.loadChannelSubscriptions(gateway: config.gatewayKey, includeDeleted: false)
                #expect(rows.count == 2 && rows.allSatisfy { $0.lastSyncedAt != nil })
            } else if phase == "unsubscribe" {
                let list = try await store.loadChannelSubscriptions(gateway: config.gatewayKey, includeDeleted: false)
                let target = try await channels.prepareChannelRemoval(subscription: #require(list.first { $0.channelId == channel }), originalConfig: config, keepHistory: true)
                _ = try await store.acceptConfirmedChannelRemoval(target)
                let claimed = try #require(try await store.claimNextPendingLocalDeletion(owner: "c3-native", leaseDuration: 30, now: Date()))
                _ = try await channels.commitPendingChannelRemoval(record: claimed, leaseOwner: "c3-native")
                try await store.completePendingLocalDeletionCleanup(id: claimed.id)
                let after = try await store.loadChannelSubscriptions(gateway: config.gatewayKey, includeDeleted: false)
                #expect(after.count == 1 && after.first?.channelId == boot["survivor_channel_id"])
            } else if phase == "logout" {
                try await store.saveServerConfig(nil)
                try await route.cleanupPreviousGatewayDeviceRoute(previousConfig: config, previousDeviceKey: device, nextConfig: nil)
                try await route.restoreProviderDeviceKey(nil, source: "c3.logout")
                let reopened = LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil)
                #expect(try await reopened.loadServerConfig() == nil)
                #expect(await reopened.cachedDeviceKey(for: "macos", backfillWakeupDefaults: false) == nil)
            } else {
                let delivery = try env("C3_DELIVERY_ID")
                let title = try env("C3_EXPECTED_TITLE")
                let body = try env("C3_EXPECTED_BODY")
                let inbox = NotificationIngressInbox(appGroupIdentifier: group)
                let markers = ProviderDeliveryAckFailureStore(appGroupIdentifier: group)
                let ingress = NotificationIngressController(platformSuffix: "macos", dataStore: store, channelSubscriptionService: service,
                    serverConfigProvider: { config }, cachedDeviceKeyProvider: { device }, beforePersistMessage: { _ in }, scheduleCountsRefresh: {},
                    recordProviderError: { error, source in runtimeErrors.append("\(source): \(error)") }, shouldDeferStartupWakeupPulls: { false },
                    notificationIngressInbox: inbox, ackFailureStore: markers)
                if phase == "direct" || phase == "ingest" {
                    let raw = try Data(contentsOf: URL(fileURLWithPath: env("C3_CAPTURE_PATH")))
                    let payload = try #require(JSONSerialization.jsonObject(with: raw) as? [String:Any])
                    #expect(payload["delivery_id"] as? String == delivery)
                    if phase == "ingest" { #expect(NotificationHandling.providerWakeupPullDeliveryId(from: payload) == delivery) }
                    let enqueued = await inbox.enqueue(codablePayload: payload.mapValues(AnyCodable.init), requestIdentifier: delivery,
                        source: "c3.actual_provider_capture", ackIdentity: nil, requiredEntryState: "durable")
                    #expect(enqueued)
                    let outcome = await ingress.mergeNotificationIngressInboxOutcome(reason: "c3.capture", allowWakeupSync: true)
                    #expect(outcome.appliedCount == 1)
                    let drain = await ingress.drainProviderDeliveryAckFailures(source: "c3." + phase)
                    if phase == "ingest" {
                        #expect(drain == .failed)
                        let pending = await markers.pendingMarkers(limit: 20, now: Date().addingTimeInterval(120))
                        #expect(pending.contains { $0.identity?.deliveryId == delivery && $0.identity?.deviceKey == device && $0.identity?.baseURL == base && $0.attemptCount > 0 })
                        #expect(!runtimeErrors.isEmpty)
                    } else { #expect(drain == .succeeded) }
                } else if phase == "recover" {
                    let before = try await store.loadMessages(deliveryId: delivery)
                    #expect(before.count == 1 && before.first?.title == title && before.first?.body == body)
                    let pending = await markers.pendingMarkers(limit: 20, now: Date().addingTimeInterval(120))
                    #expect(pending.contains { $0.identity?.deliveryId == delivery && $0.attemptCount > 0 })
                    if let due = await markers.nextAttemptDate(), due > Date() {
                        let seconds = due.timeIntervalSinceNow
                        #expect(seconds < 65)
                        try await Task.sleep(for: .seconds(seconds + 0.1))
                    }
                    #expect(await ingress.drainProviderDeliveryAckFailures(source: "c3.new_process") == .succeeded)
                    #expect(await markers.pendingMarkers(limit: 20, now: Date().addingTimeInterval(120)).isEmpty)
                } else { Issue.record("Unknown phase \(phase)") }
                let rows = try await LocalDataStore(appGroupIdentifier: group, spotlightIndexer: nil).loadMessages(deliveryId: delivery)
                #expect(rows.count == 1 && rows.first?.title == title && rows.first?.body == body)
                observation["delivery_id"] = delivery
                observation["canonical_count"] = rows.count
            }
        }
        observation["runtime_errors"] = runtimeErrors
        try write(observation,to:root.appendingPathComponent("apple-\(phase)-observations.json"))
    }
}
