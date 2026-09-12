//! Providers that talk to something over HTTP.
//!
//! Two wire formats cover every endpoint we care about. The OpenAI chat-completions shape is spoken
//! by Ollama, OpenAI, OpenRouter, vLLM and llama.cpp, so it is one implementation with a base URL
//! and a key; Anthropic's Messages API is its own shape and gets its own.
//!
//! **Blocking, by the [`Provider`] trait's design.** The calls are driven from a blocking thread
//! (`ModelInferrer` uses `spawn_blocking`), which is where a synchronous HTTP client belongs. The
//! one constraint that matters: a `reqwest::blocking::Client` must be *built* outside a Tokio
//! runtime context, which is why these are constructed when `--model` is parsed and not per call.
//!
//! **Retries are ours, not the client's.** Nesting a provider's own HTTP retry inside a retry of
//! ours multiplies attempts and hides the transience classification (`docs/17`), so the client is
//! configured with none and this module owns the decision — which is, deliberately, the same
//! [`LlmError::is_retryable`] the rest of the system reads.

use std::time::Duration;

use serde_json::{Value, json};

use crate::provider::{LlmError, ModelCaps, Provider, Request, Response, Usage};

/// How many times a call is attempted in total.
///
/// Three, and no more: a model call is the expensive part of a run, and a budget that retries a
/// rate-limited provider five times is a budget that spends the wall clock rather than saving it.
const ATTEMPTS: u32 = 3;

/// Which endpoint an OpenAI-shaped provider is.
///
/// The differences between them are small and none of them are guessable from the URL, which is why
/// this is an enum rather than a pile of booleans on a config struct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// A model on this machine. No key, and the tag it is addressed by moves — see
    /// [`OpenAiCompatible::pinned_model`].
    Ollama,
    /// api.openai.com. Its current models reject `temperature`, and the output cap is named
    /// `max_completion_tokens` rather than `max_tokens`.
    OpenAi,
    /// openrouter.ai, which fronts many providers behind the OpenAI shape.
    OpenRouter,
    /// Anything else that speaks the same protocol: vLLM, llama.cpp, a gateway.
    Other,
}

impl Flavor {
    fn id(self) -> &'static str {
        match self {
            Flavor::Ollama => "ollama",
            Flavor::OpenAi => "openai",
            Flavor::OpenRouter => "openrouter",
            Flavor::Other => "openai-compatible",
        }
    }

    /// Whether this endpoint will take a sampling temperature.
    ///
    /// OpenAI's current reasoning models reject anything but the default and answer 400. Sending
    /// none is not a loss: every request this system makes asks for temperature 0, and a provider
    /// that will not vary its sampling is doing what was wanted anyway.
    fn takes_temperature(self) -> bool {
        !matches!(self, Flavor::OpenAi)
    }

    fn output_cap_field(self) -> &'static str {
        match self {
            Flavor::OpenAi => "max_completion_tokens",
            _ => "max_tokens",
        }
    }

    /// Whether to ask for a JSON schema rather than falling back to free-form text.
    ///
    /// False for Ollama on purpose. Local models are unreliable at structured output
    /// (`docs/07-ai.md` §7), and the text-first path already exists for exactly this: a model that
    /// answers with a fenced JSON object is parsed, and one that cannot is retried as YAML.
    fn structured_output(self) -> bool {
        !matches!(self, Flavor::Ollama)
    }
}

/// An endpoint speaking `POST /chat/completions`.
#[derive(Debug)]
pub struct OpenAiCompatible {
    client: reqwest::blocking::Client,
    base: String,
    api_key: Option<String>,
    flavor: Flavor,
    context_tokens: u32,
}

impl OpenAiCompatible {
    /// `base` is everything up to `/chat/completions`, usually ending in `/v1`.
    pub fn new(base: impl Into<String>, api_key: Option<String>, flavor: Flavor) -> Result<Self, LlmError> {
        Ok(OpenAiCompatible {
            client: client()?,
            base: base.into().trim_end_matches('/').to_string(),
            api_key,
            flavor,
            // An estimate, and used only to decline gracefully rather than to size anything. The
            // endpoints disagree about how to report the real number and several will not.
            context_tokens: match flavor {
                Flavor::Ollama => 32_768,
                _ => 128_000,
            },
        })
    }

    pub fn with_context_tokens(mut self, n: u32) -> Self {
        self.context_tokens = n;
        self
    }

    /// The digest Ollama holds for a tag, so a recording names bytes rather than a label.
    ///
    /// An Ollama tag is mutable: `qwen2.5:0.5b` is whatever was last pulled under that name, and a
    /// transcript naming it says nothing about which weights answered. The digest does. Asked once,
    /// at construction, and folded into the model id the transcript records.
    ///
    /// Best effort: an endpoint that will not answer leaves the tag as it was, and the transcript
    /// is then honestly not replayable rather than falsely so.
    pub fn pinned_model(&self, tag: &str) -> String {
        if self.flavor != Flavor::Ollama {
            return tag.to_string();
        }
        let url = format!("{}/api/tags", self.base.trim_end_matches("/v1"));
        let Ok(resp) = self.client.get(&url).send() else {
            return tag.to_string();
        };
        let Ok(doc) = resp.json::<Value>() else {
            return tag.to_string();
        };
        let found = doc["models"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|m| m["name"] == tag || m["model"] == tag)
            .and_then(|m| m["digest"].as_str());
        match found {
            Some(d) if d.len() >= 12 => format!("{tag}@{}", &d[..12]),
            _ => tag.to_string(),
        }
    }

    fn body(&self, req: &Request) -> Value {
        let mut messages = vec![json!({"role": "system", "content": req.prompt.system})];
        // Stable before volatile, in separate messages, because every one of these endpoints that
        // caches at all caches on an exact prefix. Joined rather than sent one message per part:
        // the split that matters is the cache breakpoint, and the rest is noise on the wire.
        let at = req.prompt.cache_breakpoint();
        for (parts, _) in [(&req.prompt.parts[..at], true), (&req.prompt.parts[at..], false)] {
            if parts.is_empty() {
                continue;
            }
            let text = parts
                .iter()
                .map(|p| p.text.as_str())
                .collect::<Vec<_>>()
                .join("\n\n");
            messages.push(json!({"role": "user", "content": text}));
        }

        let mut body = json!({
            // The digest rides in the model id we *record*; it is not a name the endpoint knows.
            // Sending it gets `invalid model name` back, which reads as a broken provider rather
            // than as us having appended something.
            "model": addressable(&req.model),
            "messages": messages,
            self.flavor.output_cap_field(): req.max_output_tokens,
        });
        if self.flavor.takes_temperature() {
            body["temperature"] = json!(req.temperature);
        }
        if let (true, Some(schema)) = (self.flavor.structured_output(), &req.schema) {
            body["response_format"] = json!({
                "type": "json_schema",
                "json_schema": { "name": "candidate", "strict": true, "schema": schema },
            });
        }
        body
    }
}

impl Provider for OpenAiCompatible {
    fn id(&self) -> &str {
        self.flavor.id()
    }

    fn caps(&self) -> ModelCaps {
        ModelCaps {
            structured_output: self.flavor.structured_output(),
            tools: true,
            // Every one of these caches automatically on a prefix, with nothing to declare. The
            // breakpoint still shapes the request, which is why this is `true` rather than a
            // statement that the flag is ignored.
            prompt_cache: !matches!(self.flavor, Flavor::Ollama),
            context_tokens: self.context_tokens,
        }
    }

    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        let url = format!("{}/chat/completions", self.base);
        let body = self.body(req);
        let doc = send(&self.client, &url, &body, self.api_key.as_deref(), Auth::Bearer)?;

        let choice = &doc["choices"][0];
        let text = choice["message"]["content"]
            .as_str()
            .ok_or_else(|| LlmError::Malformed(format!("no message content in {doc}")))?;
        let usage = &doc["usage"];
        Ok(Response {
            text: text.to_string(),
            usage: Usage {
                input: usage["prompt_tokens"].as_u64().unwrap_or(0),
                // Reported by OpenAI, absent everywhere else, and a subset of `input` rather than
                // an addition — adding them makes a well-cached run look more expensive.
                cached_input: usage["prompt_tokens_details"]["cached_tokens"]
                    .as_u64()
                    .unwrap_or(0),
                output: usage["completion_tokens"].as_u64().unwrap_or(0),
            },
            // What answered, not what was asked for — and with the pin put back, because the
            // endpoint echoes the tag it knows and the tag alone is not a pin.
            model: match doc["model"].as_str() {
                Some(m) if m == addressable(&req.model) => req.model.clone(),
                Some(m) => m.to_string(),
                None => req.model.clone(),
            },
            stop_reason: choice["finish_reason"]
                .as_str()
                .unwrap_or("unknown")
                .to_string(),
        })
    }
}

/// Anthropic's Messages API.
#[derive(Debug)]
pub struct Anthropic {
    client: reqwest::blocking::Client,
    base: String,
    api_key: String,
}

/// The API version this speaks. A dated constant, because the wire format is versioned by it and
/// "whatever is current" is not a thing a request can ask for.
const ANTHROPIC_VERSION: &str = "2023-06-01";

impl Anthropic {
    pub fn new(api_key: impl Into<String>, base: Option<String>) -> Result<Self, LlmError> {
        Ok(Anthropic {
            client: client()?,
            base: base
                .unwrap_or_else(|| "https://api.anthropic.com".into())
                .trim_end_matches('/')
                .to_string(),
            api_key: api_key.into(),
        })
    }

    fn body(&self, req: &Request) -> Value {
        // The system prompt is stable by construction — it is the operator's instructions and never
        // contains anything from a package — so the whole of it is the cached prefix.
        let system = json!([{
            "type": "text",
            "text": req.prompt.system,
            "cache_control": {"type": "ephemeral"},
        }]);

        let at = req.prompt.cache_breakpoint();
        let mut content = Vec::new();
        for (i, part) in req.prompt.parts.iter().enumerate() {
            let mut block = json!({"type": "text", "text": part.text});
            // On the last stable block, which is where a prefix cache ends. Four breakpoints are
            // allowed per request and this uses two.
            if at > 0 && i + 1 == at {
                block["cache_control"] = json!({"type": "ephemeral"});
            }
            content.push(block);
        }

        let mut body = json!({
            "model": req.model,
            "max_tokens": req.max_output_tokens,
            "system": system,
            "messages": [{"role": "user", "content": content}],
        });
        // Sampling parameters are **removed** on the current models and answer 400, so temperature
        // is sent only where something asked for one. Zero, which is every request this system
        // makes, is what those models do anyway.
        if req.temperature != 0.0 {
            body["temperature"] = json!(req.temperature);
        }
        if let Some(schema) = &req.schema {
            body["output_config"] = json!({
                "format": {"type": "json_schema", "schema": schema},
            });
        }
        body
    }
}

impl Provider for Anthropic {
    fn id(&self) -> &str {
        "anthropic"
    }

    fn caps(&self) -> ModelCaps {
        ModelCaps {
            structured_output: true,
            tools: true,
            prompt_cache: true,
            context_tokens: 200_000,
        }
    }

    fn complete(&self, req: &Request) -> Result<Response, LlmError> {
        let url = format!("{}/v1/messages", self.base);
        let body = self.body(req);
        let doc = send(&self.client, &url, &body, Some(&self.api_key), Auth::Anthropic)?;

        // The first text block. A response may also carry thinking blocks, which are not the
        // answer and must not be concatenated into it.
        let text = doc["content"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|b| b["type"] == "text")
            .and_then(|b| b["text"].as_str())
            .ok_or_else(|| LlmError::Malformed(format!("no text block in {doc}")))?;

        let stop = doc["stop_reason"].as_str().unwrap_or("unknown").to_string();
        // A decline is an outcome with a reason attached, not a malformed answer. Reported as one
        // so a run says "the provider refused" rather than "the provider is broken".
        if stop == "refusal" {
            return Err(LlmError::Refused(
                doc["stop_details"]["explanation"]
                    .as_str()
                    .unwrap_or("no explanation given")
                    .to_string(),
            ));
        }

        let usage = &doc["usage"];
        let read = usage["cache_read_input_tokens"].as_u64().unwrap_or(0);
        Ok(Response {
            text: text.to_string(),
            usage: Usage {
                // Anthropic reports the cached and written parts *alongside* the uncached input, so
                // the total this system records is their sum. Reading `input_tokens` alone
                // understates a well-cached call by the size of its whole prefix.
                input: usage["input_tokens"].as_u64().unwrap_or(0)
                    + read
                    + usage["cache_creation_input_tokens"].as_u64().unwrap_or(0),
                cached_input: read,
                output: usage["output_tokens"].as_u64().unwrap_or(0),
            },
            model: doc["model"].as_str().unwrap_or(&req.model).to_string(),
            stop_reason: stop,
        })
    }
}

/// A model id the endpoint will accept: ours without the digest we pinned it to.
fn addressable(model: &str) -> &str {
    model.split_once('@').map(|(tag, _)| tag).unwrap_or(model)
}

/// Which header carries the key.
#[derive(Clone, Copy)]
enum Auth {
    Bearer,
    Anthropic,
}

/// One client, with the provider's own retries switched off.
fn client() -> Result<reqwest::blocking::Client, LlmError> {
    reqwest::blocking::Client::builder()
        .user_agent(concat!("trigon/", env!("CARGO_PKG_VERSION")))
        // Generous, because a large prompt on a slow model is not a hung connection. The budget
        // that stops a run is the caller's wall clock, not this.
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|e| LlmError::Transport(e.to_string()))
}

/// Post, retry what is worth retrying, and give back the parsed body.
fn send(
    client: &reqwest::blocking::Client,
    url: &str,
    body: &Value,
    key: Option<&str>,
    auth: Auth,
) -> Result<Value, LlmError> {
    let mut last = LlmError::Transport("no attempt was made".into());
    for attempt in 0..ATTEMPTS {
        if attempt > 0 {
            // Exponential, and short: a provider that is rate-limiting us wants a pause, and a
            // caller waiting on one target does not want a minute of it.
            std::thread::sleep(Duration::from_millis(500 << attempt));
        }
        let mut r = client.post(url).json(body);
        r = match (key, auth) {
            (Some(k), Auth::Bearer) => r.bearer_auth(k),
            (Some(k), Auth::Anthropic) => r
                .header("x-api-key", k)
                .header("anthropic-version", ANTHROPIC_VERSION),
            (None, _) => r,
        };

        last = match r.send() {
            Ok(resp) => {
                let status = resp.status();
                let text = resp.text().unwrap_or_default();
                if status.is_success() {
                    return serde_json::from_str(&text)
                        .map_err(|e| LlmError::Malformed(format!("{e}: {text}")));
                }
                LlmError::Http {
                    status: status.as_u16(),
                    // Clipped. A provider's 400 body can carry the whole request back, and this
                    // ends up in a log line and a failure signature.
                    body: text.chars().take(600).collect(),
                }
            }
            Err(e) => LlmError::Transport(e.to_string()),
        };
        if !trigon_core::Classify::is_retryable(&last) {
            break;
        }
    }
    Err(last)
}

/// The prompt as the providers see it, for tests that care about the wire rather than the answer.
#[cfg(test)]
fn probe(system: &str) -> Request {
    Request {
        prompt: crate::provider::Prompt::new(system).stable("prelude").volatile("this target"),
        model: "m".into(),
        max_output_tokens: 100,
        temperature: 0.0,
        schema: Some(json!({"type": "object"})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn openai_body(flavor: Flavor) -> Value {
        OpenAiCompatible::new("http://x/v1", None, flavor)
            .unwrap()
            .body(&probe("operator instructions"))
    }

    #[test]
    fn a_pinned_tag_is_recorded_but_not_sent() {
        // Found by running it: `qwen2.5:0.5b@a8b0c5157701` is what a transcript has to name, and
        // `invalid model name` is what the endpoint says if you ask for it.
        let mut req = probe("sys");
        req.model = "qwen2.5:0.5b@a8b0c5157701".into();
        let body = OpenAiCompatible::new("http://x/v1", None, Flavor::Ollama)
            .unwrap()
            .body(&req);
        assert_eq!(body["model"], "qwen2.5:0.5b");
        assert_eq!(addressable("claude-opus-5"), "claude-opus-5");
    }

    #[test]
    fn the_stable_prefix_is_sent_before_the_volatile_part() {
        // Not a nicety: every endpoint that caches at all caches on an exact prefix, and a request
        // that interleaves the two has a 0% cache-read rate while succeeding perfectly.
        let body = openai_body(Flavor::Other);
        let m = body["messages"].as_array().unwrap();
        assert_eq!(m[0]["role"], "system");
        assert_eq!(m[0]["content"], "operator instructions");
        assert_eq!(m[1]["content"], "prelude");
        assert_eq!(m[2]["content"], "this target");
    }

    #[test]
    fn openai_is_not_sent_a_temperature_and_names_its_output_cap_differently() {
        // Its current models reject a sampling temperature with a 400, and the cap is
        // `max_completion_tokens`. Both are silent failures of the "it is OpenAI-compatible" kind:
        // the request is well-formed and refused.
        let body = openai_body(Flavor::OpenAi);
        assert!(body.get("temperature").is_none(), "{body}");
        assert_eq!(body["max_completion_tokens"], 100);
        assert!(body.get("max_tokens").is_none());

        let local = openai_body(Flavor::Ollama);
        assert_eq!(local["temperature"], 0.0);
        assert_eq!(local["max_tokens"], 100);
    }

    #[test]
    fn a_schema_is_asked_for_only_where_it_is_believed() {
        assert!(openai_body(Flavor::OpenAi)["response_format"]["json_schema"]["strict"] == true);
        // Local models are unreliable at it, and the text-first fallback exists for exactly this.
        assert!(openai_body(Flavor::Ollama).get("response_format").is_none());
    }

    #[test]
    fn anthropic_caches_the_system_prompt_and_the_stable_prefix() {
        let body = Anthropic::new("k", None).unwrap().body(&probe("rules"));
        assert_eq!(body["system"][0]["cache_control"]["type"], "ephemeral");
        let content = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["cache_control"]["type"], "ephemeral");
        assert!(
            content[1].get("cache_control").is_none(),
            "a breakpoint after the volatile part caches nothing and costs a write"
        );
    }

    #[test]
    fn anthropic_is_sent_no_temperature_at_all_by_default() {
        // Sampling parameters are removed on the current models and answer 400. Every request this
        // system makes asks for zero, which is what those models do anyway.
        let body = Anthropic::new("k", None).unwrap().body(&probe("rules"));
        assert!(body.get("temperature").is_none(), "{body}");
        assert_eq!(body["output_config"]["format"]["type"], "json_schema");
    }
}
