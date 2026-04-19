use hashbrown::HashMap;

pub fn build_provider_wakeup_data(base: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for key in [
        "title",
        "delivery_id",
        "channel_id",
        "entity_type",
        "entity_id",
        "message_id",
        "event_id",
        "thing_id",
        "op_id",
        "sent_at",
        "ttl",
        "schema_version",
        "payload_version",
        "base_url",
    ] {
        if let Some(value) = base.get(key) {
            out.insert(key.to_string(), value.clone());
        }
    }
    if let Some(body) = wakeup_body_preview(base.get("body").map(String::as_str)) {
        out.insert("body".to_string(), body);
    }
    out.insert("provider_mode".to_string(), "wakeup".to_string());
    out.insert("provider_wakeup".to_string(), "1".to_string());
    out.insert("_skip_persist".to_string(), "1".to_string());
    out
}

pub fn apply_provider_wakeup_title(data: &mut HashMap<String, String>, title: Option<&str>) {
    let normalized = title
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    match normalized {
        Some(title) => {
            data.insert("title".to_string(), title);
        }
        None => {
            data.remove("title");
        }
    }
}

fn wakeup_body_preview(body: Option<&str>) -> Option<String> {
    const MAX_PREVIEW_CHARS: usize = 180;

    let normalized = body?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    if normalized.is_empty() {
        return nil_if_empty(normalized);
    }

    let mut preview = String::new();
    for ch in normalized.chars().take(MAX_PREVIEW_CHARS) {
        preview.push(ch);
    }
    nil_if_empty(preview.trim().to_string())
}

fn nil_if_empty(value: String) -> Option<String> {
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashMap;

    use super::{apply_provider_wakeup_title, build_provider_wakeup_data};

    #[test]
    fn build_provider_wakeup_data_keeps_title_when_present() {
        let base = HashMap::from([
            ("delivery_id".to_string(), "delivery-1".to_string()),
            ("title".to_string(), "Wakeup title".to_string()),
            (
                "body".to_string(),
                "Wakeup body preview that should survive".to_string(),
            ),
            (
                "base_url".to_string(),
                "https://sandbox.pushgo.dev".to_string(),
            ),
        ]);

        let wakeup = build_provider_wakeup_data(&base);
        assert_eq!(
            wakeup.get("title").map(String::as_str),
            Some("Wakeup title")
        );
        assert_eq!(
            wakeup.get("base_url").map(String::as_str),
            Some("https://sandbox.pushgo.dev")
        );
        assert_eq!(
            wakeup.get("body").map(String::as_str),
            Some("Wakeup body preview that should survive")
        );
    }

    #[test]
    fn apply_provider_wakeup_title_replaces_blank_or_missing_values() {
        let mut wakeup = HashMap::new();
        wakeup.insert("title".to_string(), "stale".to_string());

        apply_provider_wakeup_title(&mut wakeup, Some("  refreshed title  "));
        assert_eq!(
            wakeup.get("title").map(String::as_str),
            Some("refreshed title")
        );

        apply_provider_wakeup_title(&mut wakeup, Some("   "));
        assert!(!wakeup.contains_key("title"));
    }

    #[test]
    fn build_provider_wakeup_data_truncates_body_preview() {
        let long_body = "x".repeat(220);
        let wakeup = build_provider_wakeup_data(&HashMap::from([("body".to_string(), long_body)]));

        let preview = wakeup
            .get("body")
            .expect("wakeup body preview should be present");
        assert_eq!(preview.chars().count(), 180);
    }
}
