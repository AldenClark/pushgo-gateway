use super::*;

#[tokio::test]
async fn private_bindings_keep_history_for_multiple_tokens_same_device() {
    let ctx = setup_sqlite_storage("private-bindings-history").await;
    let device_id: DeviceId = [9; 16];
    let token_1 = "android-history-token-0001";
    let token_2 = "android-history-token-0002";

    ctx.storage
        .bind_private_token(device_id, Platform::ANDROID, token_1)
        .await
        .expect("bind first token should succeed");
    ctx.storage
        .bind_private_token(device_id, Platform::ANDROID, token_2)
        .await
        .expect("bind second token should succeed");

    let found_1 = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token_1)
        .await
        .expect("lookup first token should succeed");
    let found_2 = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token_2)
        .await
        .expect("lookup second token should succeed");
    assert_eq!(found_1, Some(device_id));
    assert_eq!(found_2, Some(device_id));
}

#[tokio::test]
async fn private_bindings_rebind_same_token_updates_target_device() {
    let ctx = setup_sqlite_storage("private-bindings-rebind").await;
    let old_device: DeviceId = [3; 16];
    let new_device: DeviceId = [4; 16];
    let token = "android-rebind-token-001";

    ctx.storage
        .bind_private_token(old_device, Platform::ANDROID, token)
        .await
        .expect("bind old device token should succeed");
    let old_found = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token)
        .await
        .expect("lookup token on old device should succeed");
    assert_eq!(old_found, Some(old_device));

    ctx.storage
        .bind_private_token(new_device, Platform::ANDROID, token)
        .await
        .expect("rebind token to new device should succeed");
    let new_found = ctx
        .storage
        .lookup_private_device(Platform::ANDROID, token)
        .await
        .expect("lookup token after rebind should succeed");
    assert_eq!(new_found, Some(new_device));
}
