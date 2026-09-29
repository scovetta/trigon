//! The HTTP providers against an endpoint on loopback: what reaches the wire, and what is made of
//! what comes back.
//!
//! The unit tests in `http.rs` build a request body and look at it. These go through `complete` and
//! `pinned_model` exactly as a run does, against a server bound to `127.0.0.1:0` in this process
//! that records every request it is sent and answers from a script. Nothing here reaches the
//! network, and no key is real. Every provider that sends is built `without_proxy`, so a proxy
//! configured on the host is not what answers.
//!
//! What comes back from a model endpoint is input somebody else controls, and every way of reading
//! it wrong is quiet: a truncated answer read as a finished one, a refusal read as a broken
//! provider, a 400 retried until the budget is gone.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use serde_json::{Value, json};
use trigon_ai::{
    Anthropic, Effort, Flavor, LlmError, OpenAiCompatible, Prompt, Provider, Reasoning, Request,
};
use trigon_core::Classify as _;

/// How many times a call is attempted in total: `http::ATTEMPTS`, which is private.
const ATTEMPTS: usize = 3;

/// One request, as the endpoint saw it.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    /// Names lowercased, so a lookup does not depend on how the client spelled them.
    headers: Vec<(String, String)>,
    body: Value,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An endpoint on loopback that answers each request with the next of its replies, in order.
struct Endpoint {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Endpoint {
    /// `replies` are `(status, body)`. Once they run out every request is answered 418, which is
    /// not retryable, so a test that asks more than it scripted fails at once rather than waiting.
    fn new(replies: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut replies = replies.into_iter();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&stream) else {
                    continue;
                };
                // Recorded before the answer is written, so it is in the log by the time the
                // client has read the answer and returned.
                log.lock().unwrap().push(request);
                let (status, body) = replies
                    .next()
                    .unwrap_or((418, "the test ran out of scripted replies".into()));
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Scripted\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        Endpoint { base, seen }
    }

    fn ok(body: Value) -> Self {
        Self::new(vec![(200, body.to_string())])
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn read_request(stream: &TcpStream) -> Option<Seen> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut words = line.split_whitespace();
    let method = words.next()?.to_string();
    let path = words.next()?.to_string();
    let mut headers = Vec::new();
    loop {
        let mut h = String::new();
        reader.read_line(&mut h).ok()?;
        let h = h.trim_end();
        if h.is_empty() {
            break;
        }
        let (k, v) = h.split_once(':')?;
        headers.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
    }
    let len = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; len];
    reader.read_exact(&mut body).ok()?;
    Some(Seen {
        method,
        path,
        headers,
        body: serde_json::from_slice(&body).unwrap_or(Value::Null),
    })
}

/// An address that accepts connections and never says anything on them, and reports each one as
/// it is accepted.
fn silent() -> (String, mpsc::Receiver<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (accepted, each) = mpsc::channel();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for stream in listener.incoming() {
            held.push(stream);
            let _ = accepted.send(());
        }
    });
    (base, each)
}

/// An address with nothing listening on it.
fn nothing_listening() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let base = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    base
}

fn request(model: &str) -> Request {
    Request {
        prompt: Prompt::new("operator instructions")
            .stable("prelude")
            .volatile("this target"),
        model: model.into(),
        max_output_tokens: 100,
        temperature: 0.0,
        schema: None,
        reasoning: Reasoning::Default,
        effort: None,
    }
}

/// A chat-completions answer carrying `message` and `finish_reason`, plus whatever `extra` adds at
/// the top level.
fn chat(message: Value, finish: &str, extra: Value) -> Value {
    let mut doc = json!({
        "choices": [{"index": 0, "message": message, "finish_reason": finish}],
    });
    for (k, v) in extra.as_object().unwrap() {
        doc[k] = v.clone();
    }
    doc
}

fn openai(base: &str, key: Option<&str>, flavor: Flavor) -> OpenAiCompatible {
    OpenAiCompatible::new(format!("{base}/v1"), key.map(str::to_string), flavor)
        .unwrap()
        .without_proxy()
        .unwrap()
}

// --- The OpenAI-shaped endpoints ---------------------------------------------------------------

#[test]
fn a_chat_completion_is_posted_with_the_key_as_a_bearer_and_names_who_is_asking() {
    let e = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "ok"}),
        "stop",
        json!({}),
    ));
    // A trailing slash on the base is not a second slash in the path.
    let p = OpenAiCompatible::new(
        format!("{}/v1/", e.base),
        Some("sk-test".into()),
        Flavor::OpenRouter,
    )
    .unwrap()
    .without_proxy()
    .unwrap();
    p.complete(&request("vendor/model")).unwrap();

    let seen = e.seen();
    assert_eq!(seen.len(), 1);
    let r = &seen[0];
    assert_eq!(
        (r.method.as_str(), r.path.as_str()),
        ("POST", "/v1/chat/completions")
    );
    assert_eq!(r.header("authorization"), Some("Bearer sk-test"));
    assert_eq!(
        r.header("x-api-key"),
        None,
        "the Anthropic header is Anthropic's"
    );
    // The same string every other route declares: a provider noticing our traffic should reach a
    // person rather than guess.
    assert_eq!(
        r.header("user-agent"),
        Some(trigon_politeness::user_agent().as_str())
    );
    assert_eq!(r.body["model"], "vendor/model");
    assert_eq!(r.body["messages"][0]["role"], "system");
    assert_eq!(r.body["messages"][0]["content"], "operator instructions");
}

#[test]
fn an_endpoint_configured_without_a_key_is_sent_no_authorization_at_all() {
    // A model on this machine needs no key, and an empty `Bearer ` is a malformed credential rather
    // than an absent one.
    let e = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "ok"}),
        "stop",
        json!({}),
    ));
    openai(&e.base, None, Flavor::Ollama)
        .complete(&request("qwen2.5:0.5b"))
        .unwrap();
    assert_eq!(e.seen()[0].header("authorization"), None);
}

#[test]
fn the_answer_the_reasoning_beside_it_and_what_it_cost_are_all_read() {
    let e = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "kind: flow\n", "reasoning": "because X"}),
        "stop",
        json!({
            "model": "gpt-5.1-2025-11-13",
            "usage": {
                "prompt_tokens": 1000,
                "prompt_tokens_details": {"cached_tokens": 800},
                "completion_tokens": 50,
            },
        }),
    ));
    let r = openai(&e.base, Some("k"), Flavor::OpenAi)
        .complete(&request("gpt-5.1"))
        .unwrap();
    assert_eq!(r.text, "kind: flow\n");
    // Charged at output rates and it is the derivation; a transcript holding the recipe and not
    // the reasoning can say what was proposed and never why.
    assert_eq!(r.reasoning.as_deref(), Some("because X"));
    // Cached input is a subset of input, not an addition to it.
    assert_eq!(
        (r.usage.input, r.usage.cached_input, r.usage.output),
        (1000, 800, 50)
    );
    // What answered, not what was asked for.
    assert_eq!(r.model, "gpt-5.1-2025-11-13");
    assert_eq!(r.stop_reason, "stop");
}

#[test]
fn what_an_answer_leaves_out_is_absent_rather_than_invented() {
    // An empty trace is no trace, a missing count is zero rather than an estimate, and a missing
    // model is the one that was asked for rather than a blank a transcript would record.
    let e = Endpoint::ok(json!({
        "choices": [{"message": {"role": "assistant", "content": "ok", "reasoning": ""}}],
    }));
    let r = openai(&e.base, None, Flavor::Other)
        .complete(&request("my-model"))
        .unwrap();
    assert_eq!(r.reasoning, None);
    assert_eq!(
        (r.usage.input, r.usage.cached_input, r.usage.output),
        (0, 0, 0)
    );
    assert_eq!(r.model, "my-model");
    assert_eq!(r.stop_reason, "unknown");
}

#[test]
fn a_pinned_tag_is_sent_bare_and_the_pin_is_put_back_on_what_answered() {
    // The endpoint knows the tag and not the digest we appended to it, and it echoes the tag. The
    // pin is what a transcript has to name, so it is restored rather than lost on the way back.
    let e = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "ok"}),
        "stop",
        json!({"model": "qwen2.5:0.5b"}),
    ));
    let r = openai(&e.base, None, Flavor::Ollama)
        .complete(&request("qwen2.5:0.5b@a8b0c5157701"))
        .unwrap();
    assert_eq!(e.seen()[0].body["model"], "qwen2.5:0.5b");
    assert_eq!(r.model, "qwen2.5:0.5b@a8b0c5157701");
}

#[test]
fn an_answer_cut_off_at_the_output_cap_is_truncated_rather_than_malformed_or_accepted() {
    // The walk in `propose` lowers the depth on `Truncated` and on nothing else. A reasoning model
    // that thought until the cap came back with an empty content field, which the candidate parser
    // then called malformed; one cut mid-answer came back as a success with half a recipe in it.
    let spent_thinking = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "", "reasoning": "and then"}),
        "length",
        json!({"usage": {
            "prompt_tokens": 10,
            "completion_tokens": 100,
            "completion_tokens_details": {"reasoning_tokens": 97},
        }}),
    ));
    let e = openai(&spent_thinking.base, None, Flavor::OpenRouter)
        .complete(&request("m"))
        .unwrap_err();
    assert!(
        matches!(
            e,
            LlmError::Truncated {
                limit: 100,
                thinking: 97
            }
        ),
        "{e:?}"
    );

    let cut_mid_answer = Endpoint::ok(chat(
        json!({"role": "assistant", "content": "kind: flow\nlocation: { repo: "}),
        "length",
        json!({}),
    ));
    let e = openai(&cut_mid_answer.base, None, Flavor::Ollama)
        .complete(&request("m"))
        .unwrap_err();
    assert!(
        matches!(
            e,
            LlmError::Truncated {
                limit: 100,
                thinking: 0
            }
        ),
        "{e:?}"
    );
    // The same budget produces the same truncation, so the transport does not ask again.
    assert_eq!(cut_mid_answer.seen().len(), 1);
}

#[test]
fn an_answer_with_no_message_content_is_malformed_and_asked_once() {
    let e = Endpoint::ok(json!({"choices": []}));
    let err = openai(&e.base, None, Flavor::Other)
        .complete(&request("m"))
        .unwrap_err();
    assert!(matches!(err, LlmError::Malformed(_)), "{err:?}");
    assert!(err.to_string().contains("no message content"), "{err}");
    // Malformed is the repair loop's to retry, with its own budget; retrying here as well would
    // retry inside the retry.
    assert!(!err.is_retryable());
    assert_eq!(e.seen().len(), 1);
}

#[test]
fn a_success_whose_body_is_not_json_is_malformed_rather_than_retried() {
    let e = Endpoint::new(vec![(200, "<html>a gateway said hello</html>".into())]);
    let err = openai(&e.base, None, Flavor::Other)
        .complete(&request("m"))
        .unwrap_err();
    assert!(matches!(err, LlmError::Malformed(_)), "{err:?}");
    assert!(err.to_string().contains("a gateway said hello"), "{err}");
    assert_eq!(e.seen().len(), 1);
}

#[test]
fn a_rate_limited_call_is_asked_again_and_the_later_answer_is_the_one_returned() {
    let e = Endpoint::new(vec![
        (429, r#"{"error": "slow down"}"#.into()),
        (
            200,
            chat(
                json!({"role": "assistant", "content": "second"}),
                "stop",
                json!({}),
            )
            .to_string(),
        ),
    ]);
    let r = openai(&e.base, None, Flavor::Other)
        .complete(&request("m"))
        .unwrap();
    assert_eq!(r.text, "second");
    let seen = e.seen();
    assert_eq!(seen.len(), 2);
    // The same question both times: a retry that changed the request would be a different call.
    assert_eq!(seen[0].body, seen[1].body);
}

#[test]
fn a_server_error_that_persists_is_given_up_on_after_three_attempts() {
    // Three, and no more: a budget that retries a failing provider five times spends the wall
    // clock rather than saving it. The fourth reply is never asked for.
    let mut replies = vec![(503, "busy".to_string()); ATTEMPTS];
    replies.push((
        200,
        chat(
            json!({"role": "assistant", "content": "too late"}),
            "stop",
            json!({}),
        )
        .to_string(),
    ));
    let e = Endpoint::new(replies);
    let err = openai(&e.base, None, Flavor::Other)
        .complete(&request("m"))
        .unwrap_err();
    assert!(
        matches!(&err, LlmError::Http { status: 503, body } if body == "busy"),
        "{err:?}"
    );
    assert_eq!(e.seen().len(), ATTEMPTS);
}

#[test]
fn a_client_error_is_not_retried_and_its_body_is_clipped() {
    // A 400 is a request the provider will refuse again. And its body can carry the whole request
    // back, while this error ends up in a log line and a failure signature.
    let e = Endpoint::new(vec![(400, "x".repeat(5_000))]);
    let err = openai(&e.base, Some("k"), Flavor::OpenAi)
        .complete(&request("m"))
        .unwrap_err();
    let LlmError::Http { status, body } = &err else {
        panic!("{err:?}");
    };
    assert_eq!(*status, 400);
    assert_eq!(body.chars().count(), 600);
    assert!(!err.is_retryable());
    assert_eq!(e.seen().len(), 1);
}

#[test]
fn an_endpoint_that_is_not_listening_is_a_transport_failure_worth_retrying() {
    let err = openai(&nothing_listening(), None, Flavor::Other)
        .complete(&request("m"))
        .unwrap_err();
    assert!(matches!(err, LlmError::Transport(_)), "{err:?}");
    assert!(err.is_retryable());
}

#[test]
fn a_request_is_abandoned_at_the_timeout_it_was_given() {
    // The flavour's own bound is ten minutes or an hour, and the HTTP client's built-in default is
    // thirty seconds. What is under test is that the per-request bound is the one applied, so the
    // call is held to a limit well under all three: three attempts at 200 ms, with the one and two
    // seconds of backoff between them, come to under four seconds.
    let (base, accepted) = silent();
    let p = openai(&base, None, Flavor::Other).with_timeout(Duration::from_millis(200));
    // On a thread of its own, so a bound that was not applied fails this at the limit rather than
    // holding it for as long as whichever bound was.
    let (done, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = done.send(p.complete(&request("m")));
    });
    let limit = Duration::from_secs(15);
    let err = outcome
        .recv_timeout(limit)
        .expect("still waiting at the limit, so the per-request timeout was not the bound applied")
        .unwrap_err();
    assert!(matches!(err, LlmError::Transport(_)), "{err:?}");

    // A timeout is a transport failure, which is worth asking again: each attempt reached the
    // endpoint, and none was made past the last.
    assert!(err.is_retryable());
    for n in 1..=ATTEMPTS {
        accepted
            .recv_timeout(limit)
            .unwrap_or_else(|_| panic!("attempt {n} never connected"));
    }
    assert!(
        accepted.try_recv().is_err(),
        "more than {ATTEMPTS} attempts"
    );
}

#[test]
fn each_flavour_names_itself_and_says_what_it_can_do() {
    let caps = |flavor| {
        OpenAiCompatible::new("http://127.0.0.1:9/v1", None, flavor)
            .unwrap()
            .caps()
    };
    // A schema is asked for only where it is believed: local models are unreliable at structured
    // output, and the text-first path exists for exactly them.
    assert!(!caps(Flavor::Ollama).structured_output);
    for flavor in [Flavor::OpenAi, Flavor::OpenRouter, Flavor::Other] {
        assert!(caps(flavor).structured_output, "{flavor:?}");
    }
    // Every one of them caches on a prefix, Ollama included.
    for flavor in [
        Flavor::Ollama,
        Flavor::OpenAi,
        Flavor::OpenRouter,
        Flavor::Other,
    ] {
        assert!(caps(flavor).prompt_cache, "{flavor:?}");
    }

    let ids: Vec<String> = [
        Flavor::Ollama,
        Flavor::OpenAi,
        Flavor::OpenRouter,
        Flavor::Other,
    ]
    .into_iter()
    .map(|f| {
        OpenAiCompatible::new("http://127.0.0.1:9/v1", None, f)
            .unwrap()
            .id()
            .to_string()
    })
    .collect();
    assert_eq!(ids, ["ollama", "openai", "openrouter", "openai-compatible"]);

    // The context estimate is only an estimate, and an operator who knows better can say so.
    let sized = OpenAiCompatible::new("http://127.0.0.1:9/v1", None, Flavor::Other)
        .unwrap()
        .with_context_tokens(8_192);
    assert_eq!(sized.caps().context_tokens, 8_192);

    // The reasoning an endpoint was configured with is what the caller copies into its requests.
    let quiet = OpenAiCompatible::new("http://127.0.0.1:9/v1", None, Flavor::Ollama)
        .unwrap()
        .with_reasoning(Reasoning::Off);
    assert_eq!(quiet.reasoning(), Reasoning::Off);
    assert_eq!(
        OpenAiCompatible::new("http://127.0.0.1:9/v1", None, Flavor::Ollama)
            .unwrap()
            .reasoning(),
        Reasoning::Default
    );
}

// --- Pinning an Ollama tag to its digest -------------------------------------------------------

fn tags(models: Value) -> Endpoint {
    Endpoint::ok(json!({ "models": models }))
}

#[test]
fn an_ollama_tag_is_pinned_to_the_digest_it_resolves_to() {
    let e = tags(json!([
        {"name": "llama3:8b", "model": "llama3:8b", "digest": "ffffffffffffffffffff"},
        {"name": "qwen2.5:0.5b", "model": "qwen2.5:0.5b", "digest": "a8b0c5157701e2f3a4b5c6d7"},
    ]));
    let p = openai(&e.base, None, Flavor::Ollama);
    let pinned = p.pinned_model("qwen2.5:0.5b");
    assert_eq!(pinned, "qwen2.5:0.5b@a8b0c5157701");
    // Which is what makes a recording replayable as evidence of which weights answered.
    assert!(trigon_ai::is_snapshot(&pinned));

    // Asked of Ollama's own API, beside the OpenAI-shaped one rather than under it.
    let seen = e.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("GET", "/api/tags")
    );
}

#[test]
fn a_tag_is_recognised_by_its_model_field_as_well_as_its_name() {
    let e = tags(json!([
        {"name": "registry.example/qwen", "model": "qwen2.5:0.5b", "digest": "0123456789abcdef"},
    ]));
    assert_eq!(
        openai(&e.base, None, Flavor::Ollama).pinned_model("qwen2.5:0.5b"),
        "qwen2.5:0.5b@0123456789ab"
    );
}

#[test]
fn a_tag_that_cannot_be_pinned_is_left_as_it_was_rather_than_pinned_to_something_else() {
    // Best effort, and honest about it: the tag stays a tag, and a transcript naming it then says
    // truthfully that it is not replayable.
    let unlisted = tags(json!([{"name": "llama3:8b", "digest": "ffffffffffffffffffff"}]));
    let short = tags(json!([{"name": "qwen2.5:0.5b", "digest": "a8b0c51"}]));
    let no_digest = tags(json!([{"name": "qwen2.5:0.5b"}]));
    let not_json = Endpoint::new(vec![(200, "ollama is starting".into())]);
    let no_list = Endpoint::ok(json!({"error": "no models"}));
    for e in [unlisted, short, no_digest, not_json, no_list] {
        let pinned = openai(&e.base, None, Flavor::Ollama).pinned_model("qwen2.5:0.5b");
        assert_eq!(pinned, "qwen2.5:0.5b");
        assert!(!trigon_ai::is_snapshot(&pinned));
    }
}

#[test]
fn an_ollama_that_is_not_there_leaves_the_tag_unpinned() {
    assert_eq!(
        openai(&nothing_listening(), None, Flavor::Ollama).pinned_model("qwen2.5:0.5b"),
        "qwen2.5:0.5b"
    );
}

#[test]
fn only_ollama_is_asked_for_a_digest() {
    // The tags API is Ollama's. Asking anyone else for it is a request they will answer with an
    // error, or with a document that happens to parse.
    let e = tags(json!([{"name": "m", "digest": "0123456789abcdef"}]));
    for flavor in [Flavor::OpenAi, Flavor::OpenRouter, Flavor::Other] {
        assert_eq!(
            openai(&e.base, None, flavor).pinned_model("m"),
            "m",
            "{flavor:?}"
        );
    }
    assert!(e.seen().is_empty(), "{:?}", e.seen());
}

// --- Anthropic's Messages API ------------------------------------------------------------------

fn anthropic(base: &str) -> Anthropic {
    Anthropic::new("sk-ant-test", Some(format!("{base}/")))
        .unwrap()
        .without_proxy()
        .unwrap()
}

fn message(content: Value, stop: &str, extra: Value) -> Value {
    let mut doc = json!({
        "type": "message",
        "role": "assistant",
        "content": content,
        "stop_reason": stop,
    });
    for (k, v) in extra.as_object().unwrap() {
        doc[k] = v.clone();
    }
    doc
}

#[test]
fn the_messages_api_is_sent_its_key_and_version_headers_and_no_bearer() {
    let e = Endpoint::ok(message(
        json!([{"type": "text", "text": "ok"}]),
        "end_turn",
        json!({}),
    ));
    let mut req = request("claude-haiku-4-5-20251001");
    req.temperature = 0.25;
    anthropic(&e.base).complete(&req).unwrap();

    let seen = e.seen();
    assert_eq!(seen.len(), 1);
    let r = &seen[0];
    assert_eq!(
        (r.method.as_str(), r.path.as_str()),
        ("POST", "/v1/messages")
    );
    assert_eq!(r.header("x-api-key"), Some("sk-ant-test"));
    // The wire format is versioned by this header, and "whatever is current" is not a version.
    assert_eq!(r.header("anthropic-version"), Some("2023-06-01"));
    assert_eq!(r.header("authorization"), None);
    assert_eq!(
        r.header("user-agent"),
        Some(trigon_politeness::user_agent().as_str())
    );
    assert_eq!(r.body["model"], "claude-haiku-4-5-20251001");
    assert_eq!(r.body["max_tokens"], 100);
    assert_eq!(r.body["system"][0]["text"], "operator instructions");
    // A temperature somebody asked for reaches the wire; zero is left out.
    assert_eq!(r.body["temperature"], 0.25);
}

#[test]
fn a_depth_a_caller_asks_for_is_the_depth_on_the_wire() {
    // `Request::effort` is public and its type was not: nothing outside this crate could name
    // `Effort`, so no caller could ask for less thinking — the one lever a truncated answer has —
    // and no provider outside it could state its own `default_effort`.
    let e = Endpoint::ok(message(
        json!([{"type": "text", "text": "ok"}]),
        "end_turn",
        json!({}),
    ));
    let mut req = request("claude-haiku-4-5-20251001");
    req.effort = Some(Effort::Low);
    anthropic(&e.base).complete(&req).unwrap();

    let seen = e.seen();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].body["output_config"]["effort"], "low");
}

#[test]
fn the_answer_is_the_text_block_and_the_thinking_block_is_its_reasoning() {
    // A thinking block comes first and is not the answer: concatenating it in would put the
    // derivation inside the recipe.
    let e = Endpoint::ok(message(
        json!([
            {"type": "thinking", "thinking": "the backend is pinned", "signature": "c2ln"},
            {"type": "text", "text": "kind: flow\n"},
            {"type": "text", "text": "a second block that is not the answer"},
        ]),
        "end_turn",
        json!({
            "model": "claude-haiku-4-5-20251001",
            "usage": {
                "input_tokens": 50,
                "cache_read_input_tokens": 900,
                "cache_creation_input_tokens": 100,
                "output_tokens": 40,
            },
        }),
    ));
    let r = anthropic(&e.base)
        .complete(&request("claude-haiku-4-5"))
        .unwrap();
    assert_eq!(r.text, "kind: flow\n");
    assert_eq!(r.reasoning.as_deref(), Some("the backend is pinned"));
    // Anthropic reports the cached and the written parts beside the uncached input, so the input
    // is their sum; reading `input_tokens` alone understates a cached call by its whole prefix.
    assert_eq!(r.usage.input, 1050);
    assert_eq!(r.usage.cached_input, 900);
    assert_eq!(r.usage.output, 40);
    assert_eq!(r.model, "claude-haiku-4-5-20251001");
    assert_eq!(r.stop_reason, "end_turn");
}

#[test]
fn a_trace_returned_blank_is_no_trace_and_a_missing_model_is_the_one_asked_for() {
    // `display: omitted` returns the signature with the text blank, and an empty string is not
    // evidence of anything.
    let e = Endpoint::ok(message(
        json!([
            {"type": "thinking", "thinking": "", "signature": "c2ln"},
            {"type": "text", "text": "ok"},
        ]),
        "end_turn",
        json!({}),
    ));
    let r = anthropic(&e.base)
        .complete(&request("claude-opus-5"))
        .unwrap();
    assert_eq!(r.reasoning, None);
    assert_eq!(r.model, "claude-opus-5");
    assert_eq!(
        (r.usage.input, r.usage.cached_input, r.usage.output),
        (0, 0, 0)
    );
}

#[test]
fn a_refusal_is_reported_as_one_with_its_reason_and_is_not_asked_again() {
    let e = Endpoint::ok(message(
        json!([]),
        "refusal",
        json!({"stop_details": {"explanation": "this looks like malware"}}),
    ));
    let err = anthropic(&e.base).complete(&request("m")).unwrap_err();
    assert!(
        matches!(&err, LlmError::Refused(why) if why == "this looks like malware"),
        "{err:?}"
    );
    // A policy outcome, not a broken provider, and asking again is asking the same question.
    assert_eq!(err.fault(), trigon_core::Fault::Policy);
    assert!(!err.is_retryable());
    assert_eq!(e.seen().len(), 1);

    let unexplained = Endpoint::ok(message(json!([]), "refusal", json!({})));
    let err = anthropic(&unexplained.base)
        .complete(&request("m"))
        .unwrap_err();
    assert!(
        matches!(&err, LlmError::Refused(why) if why == "no explanation given"),
        "{err:?}"
    );
}

#[test]
fn an_answer_that_spent_its_budget_thinking_is_truncated_with_what_the_thinking_cost() {
    // The real shape: one thinking block, `stop_reason: max_tokens`, and no text. Checked before
    // the text is looked for, because it is the reason there is no text.
    let e = Endpoint::ok(message(
        json!([{"type": "thinking", "thinking": "and then", "signature": "c2ln"}]),
        "max_tokens",
        json!({"usage": {
            "input_tokens": 10,
            "output_tokens": 100,
            "output_tokens_details": {"thinking_tokens": 99},
        }}),
    ));
    let err = anthropic(&e.base).complete(&request("m")).unwrap_err();
    assert!(
        matches!(
            err,
            LlmError::Truncated {
                limit: 100,
                thinking: 99
            }
        ),
        "{err:?}"
    );
    // Ours to fix, not the provider's to be blamed for.
    assert_eq!(err.fault(), trigon_core::Fault::Bug);
    assert_eq!(e.seen().len(), 1);
}

#[test]
fn an_answer_with_no_text_block_names_its_blocks_and_not_the_whole_document() {
    // A reasoning trace carries a multi-kilobyte signature, and printing the whole response put
    // the one useful fact inside thirty kilobytes of base64.
    let signature = "QUFB".repeat(8_000);
    let e = Endpoint::ok(message(
        json!([
            {"type": "thinking", "thinking": "hm", "signature": signature},
            {"type": "tool_use", "id": "t", "name": "bash", "input": {}},
        ]),
        "tool_use",
        json!({}),
    ));
    let err = anthropic(&e.base).complete(&request("m")).unwrap_err();
    assert!(matches!(err, LlmError::Malformed(_)), "{err:?}");
    let text = err.to_string();
    assert!(text.contains("[thinking, tool_use]"), "{text}");
    assert!(
        text.contains("`tool_use`"),
        "the stop reason is named: {text}"
    );
    assert!(!text.contains("QUFBQUFB"), "the signature was printed");
    assert!(text.len() < 500, "{} bytes", text.len());
}

#[test]
fn anthropic_names_itself_and_says_what_it_can_do() {
    let p = Anthropic::new("k", None).unwrap();
    assert_eq!(p.id(), "anthropic");
    let caps = p.caps();
    assert!(caps.structured_output);
    assert!(caps.prompt_cache);
    assert_eq!(caps.context_tokens, 200_000);
}
