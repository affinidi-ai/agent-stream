//! Token-safe re-hydration of a streamed (SSE) completion.
//!
//! The buffered path restores pseudonymized values in one pass over the finished
//! response ([`super::filter::rehydrate_response`]). A stream cannot do that: a
//! NER ID token such as `[PERSON_NER_001]` is emitted by the provider as a run
//! of its own sub-word tokens, so it can be split across several SSE `delta`
//! chunks. Replacing per chunk would leak half a token (`[PERSON_NER_`) to the
//! client.
//!
//! [`StreamRehydrator`] buffers the assistant content across chunk boundaries and
//! only flushes the portion that cannot still be growing into a token, replacing
//! completed tokens with their original values on the way out. It is created only
//! when a re-hydration map exists (request guard opted into `restore_in_response`);
//! surfaces without it keep the zero-cost verbatim passthrough.

use serde_json::{Value, json};

use super::filter::{RehydrationMap, TokenReplacer};

/// Streams OpenAI-shaped SSE `data:` lines through, restoring NER ID tokens in
/// `choices[0].delta.content` without ever splitting a token across the boundary
/// between two client chunks.
pub struct StreamRehydrator {
    /// Single-pass token → value replacer, built once for the whole stream.
    replacer: TokenReplacer,
    /// Longest token key — a trailing `[…` longer than this cannot be a token.
    max_token_len: usize,
    /// Incomplete trailing line bytes (a `data:` line split across network reads).
    line_buf: Vec<u8>,
    /// Assistant content held back because it might be the start of a token.
    held: String,
    /// Envelope (id / model / created) of the first chunk, reused to synthesize a
    /// flush chunk for any content still held when the stream ends.
    template: Option<Value>,
}

impl StreamRehydrator {
    /// Build a rehydrator for a non-empty map, else `None` (keep passthrough).
    pub fn new(map: RehydrationMap) -> Option<Self> {
        let max_token_len = map
            .keys()
            .map(String::len)
            .max()
            .unwrap_or(1);
        let replacer = TokenReplacer::new(&map)?;
        Some(Self {
            replacer,
            max_token_len,
            line_buf: Vec::new(),
            held: String::new(),
            template: None,
        })
    }

    /// Feed a slice of the upstream SSE stream and return the bytes to forward to
    /// the client now (complete lines only; partial content may be held back).
    pub fn feed(
        &mut self,
        bytes: &[u8],
    ) -> Vec<u8> {
        self.line_buf
            .extend_from_slice(bytes);
        let mut out = Vec::new();
        // `\n` never appears inside a UTF-8 multi-byte sequence, so splitting the
        // raw byte stream on it keeps each line individually decodable.
        while let Some(pos) = self
            .line_buf
            .iter()
            .position(|&b| b == b'\n')
        {
            let line: Vec<u8> = self
                .line_buf
                .drain(..=pos)
                .collect();
            self.process_line(&line, &mut out);
        }
        out
    }

    /// Flush any buffered partial line and held content when the stream ends.
    pub fn finish(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.line_buf.is_empty() {
            let line = std::mem::take(&mut self.line_buf);
            self.process_line(&line, &mut out);
        }
        self.flush_held(&mut out);
        out
    }

    fn process_line(
        &mut self,
        line: &[u8],
        out: &mut Vec<u8>,
    ) {
        let Ok(text) = std::str::from_utf8(line) else {
            out.extend_from_slice(line);
            return;
        };
        let body = text
            .trim_end_matches('\n')
            .trim_end_matches('\r');
        let Some(rest) = body.strip_prefix("data:") else {
            out.extend_from_slice(line);
            return;
        };
        let payload = rest.trim();
        if payload.is_empty() {
            out.extend_from_slice(line);
            return;
        }
        if payload == "[DONE]" {
            self.flush_held(out);
            out.extend_from_slice(line);
            return;
        }
        let Ok(mut chunk) = serde_json::from_str::<Value>(payload) else {
            out.extend_from_slice(line);
            return;
        };
        if self.template.is_none() {
            self.template = Some(chunk.clone());
        }
        match delta_content(&chunk) {
            Some(content) => {
                let mut combined = std::mem::take(&mut self.held);
                combined.push_str(content);
                let split = safe_split(&combined, self.max_token_len);
                let flushed = self.replace_tokens(&combined[..split]);
                self.held = combined[split..].to_string();
                set_delta_content(&mut chunk, flushed);
                push_data_line(out, &chunk);
            }
            None => {
                // Role / finish / usage chunk: emit any held content first so it
                // never arrives after a finish_reason or `[DONE]`.
                self.flush_held(out);
                out.extend_from_slice(line);
            }
        }
    }

    fn flush_held(
        &mut self,
        out: &mut Vec<u8>,
    ) {
        if self.held.is_empty() {
            return;
        }
        let held = std::mem::take(&mut self.held);
        let restored = self.replace_tokens(&held);
        let mut chunk = self
            .template
            .clone()
            .unwrap_or_else(|| json!({ "object": "chat.completion.chunk", "choices": [{ "index": 0 }] }));
        if let Some(first) = chunk
            .get_mut("choices")
            .and_then(Value::as_array_mut)
            .and_then(|c| c.first_mut())
        {
            first["delta"] = json!({ "content": restored });
            first["finish_reason"] = Value::Null;
        }
        push_data_line(out, &chunk);
    }

    fn replace_tokens(
        &self,
        text: &str,
    ) -> String {
        self.replacer.replace(text)
    }
}

/// Index up to which `text` is safe to emit: everything before a trailing `[…`
/// that could still grow into a NER ID token. Returns `text.len()` when nothing
/// needs to be held.
fn safe_split(
    text: &str,
    max_token_len: usize,
) -> usize {
    match text.rfind('[') {
        None => text.len(),
        Some(open) => {
            let tail = &text[open..];
            // Closed bracket, or a run too long to be any token → nothing pending.
            if tail.contains(']') || tail.len() > max_token_len {
                text.len()
            } else {
                open
            }
        }
    }
}

fn delta_content(chunk: &Value) -> Option<&str> {
    chunk
        .get("choices")?
        .as_array()?
        .first()?
        .get("delta")?
        .get("content")?
        .as_str()
}

fn set_delta_content(
    chunk: &mut Value,
    content: String,
) {
    if let Some(first) = chunk
        .get_mut("choices")
        .and_then(Value::as_array_mut)
        .and_then(|c| c.first_mut())
        && let Some(delta) = first
            .get_mut("delta")
            .filter(|d| d.is_object())
    {
        delta["content"] = Value::String(content);
    }
}

fn push_data_line(
    out: &mut Vec<u8>,
    chunk: &Value,
) {
    out.extend_from_slice(b"data: ");
    out.extend_from_slice(chunk.to_string().as_bytes());
    out.extend_from_slice(b"\n\n");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> RehydrationMap {
        let mut m = RehydrationMap::new();
        m.insert("[PERSON_NER_001]".to_string(), "John Smith".to_string());
        m.insert("[EMAIL_NER_001]".to_string(), "john@example.com".to_string());
        m
    }

    fn chunk(content: &str) -> String {
        format!("data: {}\n\n", json!({ "choices": [{ "index": 0, "delta": { "content": content } }] }))
    }

    /// Collect the assistant content the client sees across `feed` + `finish`.
    fn client_content(out: &[u8]) -> String {
        let text = String::from_utf8(out.to_vec()).unwrap();
        let mut acc = String::new();
        for line in text.lines() {
            let Some(payload) = line.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            if payload.is_empty() || payload == "[DONE]" {
                continue;
            }
            if let Ok(v) = serde_json::from_str::<Value>(payload)
                && let Some(c) = delta_content(&v)
            {
                acc.push_str(c);
            }
        }
        acc
    }

    #[test]
    fn passthrough_when_token_arrives_whole() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let mut out = rh.feed(chunk("Hi [PERSON_NER_001]!").as_bytes());
        out.extend(rh.finish());
        assert_eq!(client_content(&out), "Hi John Smith!");
    }

    #[test]
    fn token_split_across_chunks_is_restored_once_whole() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let mut out = Vec::new();
        for piece in ["Hello ", "[PERSON", "_NER_", "001]", ", welcome"] {
            out.extend(rh.feed(chunk(piece).as_bytes()));
        }
        out.extend(rh.finish());
        let seen = client_content(&out);
        assert_eq!(seen, "Hello John Smith, welcome");
        // The partial token is never leaked mid-stream.
        assert!(
            !String::from_utf8(out)
                .unwrap()
                .contains("PERSON_NEAR")
        );
    }

    #[test]
    fn multiple_tokens_across_chunks() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let mut out = Vec::new();
        for piece in ["[PERSON", "_NER_001] <", "[EMAIL_NER_", "001]>"] {
            out.extend(rh.feed(chunk(piece).as_bytes()));
        }
        out.extend(rh.finish());
        assert_eq!(client_content(&out), "John Smith <john@example.com>");
    }

    #[test]
    fn line_split_across_network_reads() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let full = chunk("hi [PERSON_NER_001]");
        let (a, b) = full.split_at(full.len() / 2);
        let mut out = rh.feed(a.as_bytes());
        out.extend(rh.feed(b.as_bytes()));
        out.extend(rh.finish());
        assert_eq!(client_content(&out), "hi John Smith");
    }

    #[test]
    fn unclosed_bracket_is_flushed_at_end() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let mut out = rh.feed(chunk("array[0 stays literal").as_bytes());
        out.extend(rh.finish());
        assert_eq!(client_content(&out), "array[0 stays literal");
    }

    #[test]
    fn done_and_finish_chunks_pass_through() {
        let mut rh = StreamRehydrator::new(map()).unwrap();
        let mut out = rh.feed(chunk("[PERSON_NER_001]").as_bytes());
        out.extend(rh.feed(b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n"));
        out.extend(rh.feed(b"data: [DONE]\n\n"));
        out.extend(rh.finish());
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("[DONE]"));
        assert!(text.contains("finish_reason"));
        assert!(text.contains("John Smith"));
    }

    #[test]
    fn empty_map_is_not_rehydrated() {
        assert!(StreamRehydrator::new(RehydrationMap::new()).is_none());
    }
}
