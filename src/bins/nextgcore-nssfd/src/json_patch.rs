//! Minimal RFC 6902 JSON Patch engine.
//!
//! TS 29.531 NSSAIAvailability PATCH operations carry a `PatchDocument`
//! (array of RFC 6902 `PatchItem`s, content type `application/json-patch+json`),
//! NOT an RFC 7396 merge-patch. This module applies such documents to a
//! `serde_json::Value` with full add/remove/replace/test/copy/move support
//! and RFC 6901 pointer semantics (`~0`/`~1` unescaping, `-` array append).

use serde_json::Value;

/// Apply an RFC 6902 patch document (JSON array of operations) to `doc`.
///
/// On error the document may be partially modified; callers should apply to
/// a clone and only commit on success (all call sites in this crate do so).
pub fn apply_patch(doc: &mut Value, patch: &Value) -> Result<(), String> {
    let ops = patch
        .as_array()
        .ok_or_else(|| "patch document must be a JSON array".to_string())?;
    if ops.is_empty() {
        return Err("patch document must contain at least one operation".to_string());
    }
    for (i, op) in ops.iter().enumerate() {
        apply_op(doc, op).map_err(|e| format!("op[{i}]: {e}"))?;
    }
    Ok(())
}

fn apply_op(doc: &mut Value, op: &Value) -> Result<(), String> {
    let op_name = op
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'op'".to_string())?;
    let path = op
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing 'path'".to_string())?;
    let tokens = split_pointer(path)?;

    match op_name {
        "add" => {
            let value = op.get("value").ok_or("'add' requires 'value'")?.clone();
            add_value(doc, &tokens, value)
        }
        "replace" => {
            let value = op.get("value").ok_or("'replace' requires 'value'")?.clone();
            if get_value(doc, &tokens).is_none() {
                return Err(format!("'replace' target does not exist: {path}"));
            }
            remove_value(doc, &tokens)?;
            add_value(doc, &tokens, value)
        }
        "remove" => remove_value(doc, &tokens).map(|_| ()),
        "test" => {
            let expected = op.get("value").ok_or("'test' requires 'value'")?;
            let actual = get_value(doc, &tokens)
                .ok_or_else(|| format!("'test' target does not exist: {path}"))?;
            if actual == expected {
                Ok(())
            } else {
                Err(format!("'test' failed at {path}"))
            }
        }
        "copy" => {
            let from = op
                .get("from")
                .and_then(|v| v.as_str())
                .ok_or("'copy' requires 'from'")?;
            let from_tokens = split_pointer(from)?;
            let value = get_value(doc, &from_tokens)
                .ok_or_else(|| format!("'copy' source does not exist: {from}"))?
                .clone();
            add_value(doc, &tokens, value)
        }
        "move" => {
            let from = op
                .get("from")
                .and_then(|v| v.as_str())
                .ok_or("'move' requires 'from'")?;
            let from_tokens = split_pointer(from)?;
            let value = remove_value(doc, &from_tokens)?;
            add_value(doc, &tokens, value)
        }
        other => Err(format!("unsupported op '{other}'")),
    }
}

/// Split an RFC 6901 JSON pointer into unescaped reference tokens.
fn split_pointer(pointer: &str) -> Result<Vec<String>, String> {
    if pointer.is_empty() {
        return Err("whole-document pointer \"\" is not supported here".to_string());
    }
    if !pointer.starts_with('/') {
        return Err(format!("invalid JSON pointer: {pointer}"));
    }
    Ok(pointer[1..]
        .split('/')
        .map(|t| t.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn get_value<'a>(doc: &'a Value, tokens: &[String]) -> Option<&'a Value> {
    let mut current = doc;
    for token in tokens {
        current = match current {
            Value::Object(map) => map.get(token)?,
            Value::Array(arr) => arr.get(token.parse::<usize>().ok()?)?,
            _ => return None,
        };
    }
    Some(current)
}

fn get_parent_mut<'a>(doc: &'a mut Value, tokens: &[String]) -> Result<&'a mut Value, String> {
    let mut current = doc;
    for token in &tokens[..tokens.len() - 1] {
        current = match current {
            Value::Object(map) => map
                .get_mut(token)
                .ok_or_else(|| format!("path segment not found: {token}"))?,
            Value::Array(arr) => {
                let idx = token
                    .parse::<usize>()
                    .map_err(|_| format!("invalid array index: {token}"))?;
                arr.get_mut(idx)
                    .ok_or_else(|| format!("array index out of bounds: {idx}"))?
            }
            _ => return Err(format!("cannot traverse into scalar at: {token}")),
        };
    }
    Ok(current)
}

fn add_value(doc: &mut Value, tokens: &[String], value: Value) -> Result<(), String> {
    let last = tokens.last().expect("tokens non-empty").clone();
    let parent = get_parent_mut(doc, tokens)?;
    match parent {
        Value::Object(map) => {
            map.insert(last, value);
            Ok(())
        }
        Value::Array(arr) => {
            if last == "-" {
                arr.push(value);
                Ok(())
            } else {
                let idx = last
                    .parse::<usize>()
                    .map_err(|_| format!("invalid array index: {last}"))?;
                if idx > arr.len() {
                    return Err(format!("array index out of bounds: {idx}"));
                }
                arr.insert(idx, value);
                Ok(())
            }
        }
        _ => Err("cannot add into a scalar value".to_string()),
    }
}

fn remove_value(doc: &mut Value, tokens: &[String]) -> Result<Value, String> {
    let last = tokens.last().expect("tokens non-empty").clone();
    let parent = get_parent_mut(doc, tokens)?;
    match parent {
        Value::Object(map) => map
            .remove(&last)
            .ok_or_else(|| format!("member not found: {last}")),
        Value::Array(arr) => {
            let idx = last
                .parse::<usize>()
                .map_err(|_| format!("invalid array index: {last}"))?;
            if idx >= arr.len() {
                return Err(format!("array index out of bounds: {idx}"));
            }
            Ok(arr.remove(idx))
        }
        _ => Err("cannot remove from a scalar value".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_add_object_member() {
        let mut doc = json!({"a": 1});
        apply_patch(&mut doc, &json!([{"op": "add", "path": "/b", "value": 2}])).unwrap();
        assert_eq!(doc, json!({"a": 1, "b": 2}));
    }

    #[test]
    fn test_add_array_append_and_insert() {
        let mut doc = json!({"list": [1, 3]});
        apply_patch(
            &mut doc,
            &json!([
                {"op": "add", "path": "/list/1", "value": 2},
                {"op": "add", "path": "/list/-", "value": 4}
            ]),
        )
        .unwrap();
        assert_eq!(doc, json!({"list": [1, 2, 3, 4]}));
    }

    #[test]
    fn test_replace_and_remove() {
        let mut doc = json!({"a": {"b": 1}, "c": [10, 20]});
        apply_patch(
            &mut doc,
            &json!([
                {"op": "replace", "path": "/a/b", "value": 5},
                {"op": "remove", "path": "/c/0"}
            ]),
        )
        .unwrap();
        assert_eq!(doc, json!({"a": {"b": 5}, "c": [20]}));
    }

    #[test]
    fn test_replace_missing_target_fails() {
        let mut doc = json!({"a": 1});
        let err = apply_patch(
            &mut doc,
            &json!([{"op": "replace", "path": "/missing", "value": 1}]),
        )
        .unwrap_err();
        assert!(err.contains("does not exist"));
    }

    #[test]
    fn test_test_op() {
        let mut doc = json!({"a": 1});
        assert!(apply_patch(&mut doc, &json!([{"op": "test", "path": "/a", "value": 1}])).is_ok());
        assert!(apply_patch(&mut doc, &json!([{"op": "test", "path": "/a", "value": 2}])).is_err());
    }

    #[test]
    fn test_move_and_copy() {
        let mut doc = json!({"a": 1, "b": {}});
        apply_patch(
            &mut doc,
            &json!([
                {"op": "copy", "from": "/a", "path": "/b/copied"},
                {"op": "move", "from": "/a", "path": "/b/moved"}
            ]),
        )
        .unwrap();
        assert_eq!(doc, json!({"b": {"copied": 1, "moved": 1}}));
    }

    #[test]
    fn test_pointer_unescaping() {
        let mut doc = json!({"a/b": {"x~y": 1}});
        assert!(apply_patch(
            &mut doc,
            &json!([{"op": "test", "path": "/a~1b/x~0y", "value": 1}])
        )
        .is_ok());
    }

    #[test]
    fn test_invalid_documents() {
        let mut doc = json!({});
        assert!(apply_patch(&mut doc, &json!({})).is_err());
        assert!(apply_patch(&mut doc, &json!([])).is_err());
        assert!(apply_patch(&mut doc, &json!([{"op": "bogus", "path": "/a"}])).is_err());
        assert!(apply_patch(&mut doc, &json!([{"op": "add", "value": 1}])).is_err());
        assert!(apply_patch(
            &mut doc,
            &json!([{"op": "add", "path": "no-slash", "value": 1}])
        )
        .is_err());
    }
}
