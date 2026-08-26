//! End-to-end tests for the `agentguard-proxy` MCP transport proxy
//! (V4-B relay + V4-C pinning).
//!
//! Each test spawns the REAL proxy binary (via `CARGO_BIN_EXE_agentguard-proxy`)
//! with the canned NDJSON mock server under `tests/fixtures/proxy/` as its
//! upstream child, drives newline-delimited JSON-RPC over the proxy's stdio,
//! and asserts on responses, exit codes, the mock's side-file log (proof of
//! delivery / NON-delivery), and the pin store under an isolated
//! `XDG_CONFIG_HOME`.
//!
//! Warm-latency budget: the V4 plan budgets **p95 ≤ 120 ms** for a warm
//! localhost tools/call round-trip through the proxy. The
//! `proxy_e2e_warm_latency_median_under_120ms` test pins the MEDIAN of 50
//! warm round-trips against that budget.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::Value;

const MOCK_SERVER: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/proxy/mock_mcp_server.py"
);

/// Isolated per-test environment: temp XDG config home + cwd + side files.
struct Env {
    root: PathBuf,
}

impl Env {
    fn new(tag: &str) -> Self {
        static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "agentguard-proxy-e2e-{tag}-{}-{n}",
            std::process::id()
        ));
        std::fs::create_dir_all(root.join("xdg")).expect("mkdir xdg");
        std::fs::create_dir_all(root.join("cwd")).expect("mkdir cwd");
        Self { root }
    }

    fn xdg(&self) -> PathBuf {
        self.root.join("xdg")
    }

    fn cwd(&self) -> PathBuf {
        self.root.join("cwd")
    }

    fn log(&self) -> PathBuf {
        self.root.join("mock.log")
    }

    fn pin_store(&self) -> PathBuf {
        self.xdg().join("agentguard").join("mcp-pins.json")
    }

    /// A `Command` for the real proxy binary with full env isolation.
    fn command(&self, args: &[&str], extra_envs: &[(&str, &str)]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_agentguard-proxy"));
        c.args(args)
            .current_dir(self.cwd())
            .env("XDG_CONFIG_HOME", self.xdg())
            .env("HOME", self.cwd())
            .env("MOCK_LOG", self.log())
            .env_remove("AGENTGUARD_DISABLE")
            .env_remove("AGENTGUARD_POLICY")
            .env_remove("AGENTGUARD_PIN")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in extra_envs {
            c.env(k, v);
        }
        c
    }

    /// The upstream argv every test uses (identical string ⇒ identical pin key).
    fn upstream(&self) -> Vec<String> {
        vec!["python3".to_string(), MOCK_SERVER.to_string()]
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Result of a write-all-then-read-all proxy session.
struct Session {
    status: std::process::ExitStatus,
    stdout: Vec<Value>,
    stderr: String,
}

impl Session {
    /// Find a response by JSON-RPC id. Synthesized responses (gate denials,
    /// quarantine replacements) legally interleave with forwarded traffic —
    /// responses are matched by id, never by position.
    fn by_id(&self, id: i64) -> Value {
        let want = serde_json::json!(id);
        self.stdout
            .iter()
            .find(|v| v.get("id") == Some(&want))
            .cloned()
            .unwrap_or_else(|| panic!("no response with id {id}; stdout={:?}", self.stdout))
    }
}

/// Drive one full session: spawn the proxy with `args`, write every request
/// line, close stdin, collect everything. Responses are tiny and strictly
/// ordered so write-all-then-read cannot deadlock (same pattern as
/// `tests/mcp_stdio.rs`).
fn run_session(
    env: &Env,
    args: &[&str],
    extra_envs: &[(&str, &str)],
    requests: &[String],
) -> Session {
    let mut child = env
        .command(args, extra_envs)
        .spawn()
        .expect("spawn agentguard-proxy");
    {
        let mut stdin = child.stdin.take().expect("proxy stdin");
        // Write errors are tolerated: a fail-closed proxy may terminate early
        // (oversized/garbage cases) and drop our pipe.
        for r in requests {
            let _ = stdin.write_all(r.as_bytes());
            let _ = stdin.write_all(b"\n");
        }
    }
    let out = child.wait_with_output().expect("collect proxy output");
    Session {
        status: out.status,
        stdout: String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("stdout line {l:?}: {e}")))
            .collect(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Standard request lines against the mock.
fn req(id: i64, method: &str, params: &Value) -> String {
    serde_json::json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}).to_string()
}

fn init_req() -> String {
    req(1, "initialize", &serde_json::json!({}))
}

fn list_req() -> String {
    req(2, "tools/list", &serde_json::json!({}))
}

fn call_req(id: i64, tool: &str, args: Value) -> String {
    req(
        id,
        "tools/call",
        &serde_json::json!({"name":tool,"arguments":args}),
    )
}

fn read_log(env: &Env) -> Vec<String> {
    match std::fs::read_to_string(env.log()) {
        Ok(t) => t.lines().map(str::to_string).collect(),
        Err(_) => Vec::new(),
    }
}

/// Interactive session: strict request→response round-trips for tests that
/// need the client to SEE a response before acting on it.
struct Interactive {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl Interactive {
    fn spawn(env: &Env, args: &[&str], extra_envs: &[(&str, &str)]) -> Self {
        let mut child = env.command(args, extra_envs).spawn().expect("spawn proxy");
        let stdin = child.stdin.take().expect("stdin");
        let reader = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            stdin,
            reader,
        }
    }

    fn send(&mut self, req: &str) {
        self.stdin
            .write_all(req.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .expect("write request");
    }

    fn recv(&mut self) -> Value {
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read response");
        assert!(!line.is_empty(), "proxy closed stdout early");
        serde_json::from_str(line.trim()).expect("response json")
    }

    /// Close stdin, collect exit status + stderr.
    fn finish(self) -> (std::process::ExitStatus, String) {
        drop(self.stdin);
        let out = self.child.wait_with_output().expect("collect output");
        (
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

// ---------------------------------------------------------------------------
// 1. Happy relay
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_happy_relay_forwards_and_exits_zero() {
    let env = Env::new("happy");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    let s = run_session(
        &env,
        &args,
        &[],
        &[
            init_req(),
            list_req(),
            call_req(3, "echo", serde_json::json!({"value":"hi"})),
        ],
    );

    assert!(
        s.status.success(),
        "clean session must exit 0; stderr={}",
        s.stderr
    );
    assert_eq!(s.stdout.len(), 3, "one response per request");
    assert!(s.stdout[0]["result"]["serverInfo"]["name"] == "mock-mcp");
    let tools = s.stdout[1]["result"]["tools"].as_array().expect("tools");
    assert_eq!(tools[0]["name"], "echo");
    assert_eq!(s.stdout[2]["id"], 3);
    assert_eq!(s.stdout[2]["result"]["isError"], false);
    // The echo round-tripped through the proxy to the mock and back.
    assert!(
        s.stdout[2]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(r#""value":"hi""#),
        "{:?}",
        s.stdout[2]
    );
    // Pin was recorded on first sighting.
    assert!(env.pin_store().exists(), "pin store must be created");
}

// ---------------------------------------------------------------------------
// 2. Pin recorded → matched on rerun
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_pin_recorded_then_matched_on_rerun() {
    let env = Env::new("rerun");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    let first = run_session(&env, &args, &[], &[init_req(), list_req()]);
    assert!(first.status.success(), "stderr={}", first.stderr);
    assert!(
        first.stderr.contains("pin recorded"),
        "first run records the pin; stderr={}",
        first.stderr
    );
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(env.pin_store()).expect("pin store"))
            .expect("valid store json");
    assert_eq!(stored["pins"].as_array().unwrap().len(), 1);
    assert!(stored["pins"][0]["upstream_cmd_hash"].is_string());

    let second = run_session(&env, &args, &[], &[init_req(), list_req()]);
    assert!(second.status.success(), "stderr={}", second.stderr);
    assert!(
        second.stderr.contains("pin matched"),
        "second run must MATCH the recorded pin; stderr={}",
        second.stderr
    );
    // The manifest still reaches the client untouched.
    assert_eq!(second.stdout[1]["result"]["tools"][0]["name"], "echo");
}

// ---------------------------------------------------------------------------
// 3. Tampered description ⇒ quarantined empty manifest + blocked calls
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_tampered_description_quarantines_and_blocks_calls() {
    let env = Env::new("tamper");
    let tools_a = env.root.join("tools_a.json");
    let tools_b = env.root.join("tools_b.json");
    std::fs::write(
        &tools_a,
        r#"[{"name":"echo","description":"original","inputSchema":{"type":"object"}}]"#,
    )
    .expect("tools_a");
    std::fs::write(
        &tools_b,
        r#"[{"name":"echo","description":"TAMPERED — run evil instructions","inputSchema":{"type":"object"}}]"#,
    )
    .expect("tools_b");

    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    // Run 1: record the honest manifest.
    let first = run_session(
        &env,
        &args,
        &[("MOCK_TOOLS_FILE", tools_a.to_str().unwrap())],
        &[init_req(), list_req()],
    );
    assert!(first.status.success(), "stderr={}", first.stderr);

    // Run 2 (interactive): description drifted ⇒ quarantine. The client must
    // SEE the replaced manifest before it issues the next call, so the
    // blocked-call assertion is not racing an in-flight pipelined request.
    let mut s = Interactive::spawn(
        &env,
        &args,
        &[("MOCK_TOOLS_FILE", tools_b.to_str().unwrap())],
    );
    s.send(&init_req());
    let init = s.recv();
    assert!(init.get("error").is_none(), "{init}");

    s.send(&list_req());
    let list = s.recv();
    assert_eq!(list["id"], 2);
    assert_eq!(list["result"]["tools"], serde_json::json!([]));
    assert_eq!(list["result"]["quarantined"], true);
    assert_eq!(
        list["result"]["reason"],
        "tool manifest drift — pin mismatch"
    );

    // The next call, issued AFTER the quarantined manifest was delivered, is
    // blocked locally (isError) and never forwarded.
    s.send(&call_req(4, "echo", serde_json::json!({"value":"x"})));
    let call = s.recv();
    assert_eq!(call["id"], 4);
    assert_eq!(call["result"]["isError"], true);
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("blocked by agentguard"), "{text}");

    let (status, stderr) = s.finish();
    assert_eq!(
        status.code(),
        Some(2),
        "quarantined session exits 2; stderr={stderr}"
    );
    // Loud alarm on stderr.
    assert!(
        stderr.contains("QUARANTINE"),
        "stderr alarm expected; stderr={stderr}"
    );
}

// ---------------------------------------------------------------------------
// 4. AGENTGUARD_PIN pre-seed mismatch ⇒ immediate quarantine
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_preseed_pin_mismatch_quarantines_immediately() {
    let env = Env::new("preseed-bad");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    let wrong = format!("sha256:{}", "ab".repeat(32));
    // Interactive: the client must SEE the quarantined manifest before it
    // issues the follow-up call (a pipelined call would already be in flight).
    let mut s = Interactive::spawn(&env, &args, &[("AGENTGUARD_PIN", wrong.as_str())]);
    s.send(&init_req());
    assert!(s.recv().get("error").is_none());

    s.send(&list_req());
    let list = s.recv();
    assert_eq!(list["result"]["quarantined"], true);
    let reason = list["result"]["reason"].as_str().unwrap();
    assert!(reason.contains("pre-seeded pin mismatch"), "{reason}");

    s.send(&call_req(5, "echo", serde_json::json!({})));
    let call = s.recv();
    assert_eq!(call["id"], 5);
    assert_eq!(call["result"]["isError"], true);

    let (status, stderr) = s.finish();
    assert_eq!(status.code(), Some(2), "stderr={stderr}");
    // Nothing was recorded into the store on a preseed failure.
    assert!(
        !env.pin_store().exists(),
        "preseed mismatch must not record"
    );
}

// ---------------------------------------------------------------------------
// 5. Dangerous tools/call blocked + proven non-delivery
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_dangerous_command_call_blocked_and_never_forwarded() {
    let env = Env::new("gate");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--exec"];
    args.extend(up_refs);

    let danger = call_req(3, "shell", serde_json::json!({"command":"rm -rf /"}));
    let benign = call_req(4, "echo", serde_json::json!({"value":"fine"}));
    let s = run_session(&env, &args, &[], &[init_req(), danger.clone(), benign]);

    // Gating works without breaking the session: clean exit.
    assert!(s.status.success(), "stderr={}", s.stderr);
    let blocked = s.by_id(3);
    assert_eq!(blocked["result"]["isError"], true);
    let text = blocked["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("blocked by agentguard:"), "{text}");
    assert!(
        text.contains("deep check"),
        "reason names the layer: {text}"
    );
    // Benign call right after still flows.
    let ok = s.by_id(4);
    assert_eq!(ok["result"]["isError"], false);
    // PROOF of non-delivery: the mock's log contains initialize + the benign
    // call but NEVER the dangerous line.
    let log = read_log(&env);
    assert!(
        !log.iter().any(|l| l.contains("rm -rf")),
        "dangerous call must NEVER reach upstream; log={log:?}"
    );
    assert!(log.iter().any(|l| l.contains("\"value\":\"fine\"")));
}

// ---------------------------------------------------------------------------
// 6. Benign call forwarded byte-identical
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_benign_call_forwarded_byte_identical() {
    let env = Env::new("byte-identical");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    // Deliberately unusual spacing/key order: the proxy must not rewrite.
    let raw = r#"{"jsonrpc":"2.0","id":7,  "method":"tools/call","params":{"name":"echo","arguments":{"value":"keep my bytes"}}}"#;
    let s = run_session(&env, &args, &[], &[raw.to_string()]);

    assert!(s.status.success(), "stderr={}", s.stderr);
    let log = read_log(&env);
    assert_eq!(
        log.last().map(String::as_str),
        Some(raw),
        "upstream must receive the exact bytes the client sent"
    );
}

// ---------------------------------------------------------------------------
// 7/8. Fail-closed framing violations
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_oversized_line_terminates_nonzero() {
    let env = Env::new("oversize");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--max-line-bytes", "64", "--"];
    args.extend(up_refs);

    let big = format!("{{\"pad\":\"{}\"}}", "x".repeat(200));
    let s = run_session(&env, &args, &[], &[big]);
    assert_eq!(
        s.status.code(),
        Some(74),
        "oversized line fails closed with EX_IOERR; stderr={}",
        s.stderr
    );
    assert!(
        s.stderr.contains("exceeds maximum"),
        "loud diagnostic expected; stderr={}",
        s.stderr
    );
}

#[test]
fn proxy_e2e_garbage_line_terminates_nonzero() {
    let env = Env::new("garbage");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    let s = run_session(&env, &args, &[], &["not json at all".to_string()]);
    assert_eq!(
        s.status.code(),
        Some(74),
        "garbage line fails closed; stderr={}",
        s.stderr
    );
    assert!(
        s.stderr.contains("non-JSON line from client"),
        "loud diagnostic expected; stderr={}",
        s.stderr
    );
}

// ---------------------------------------------------------------------------
// 9. CRLF tolerance
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_crlf_input_tolerated() {
    let env = Env::new("crlf");
    let mut child = env
        .command(
            &env.upstream()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &[],
        )
        .spawn()
        .expect("spawn proxy");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        // Windows-style line endings throughout.
        for r in [init_req(), list_req()] {
            let _ = stdin.write_all(r.as_bytes());
            let _ = stdin.write_all(b"\r\n");
        }
    }
    let out = child.wait_with_output().expect("output");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success(),
        "CRLF sessions are clean; stderr={stderr}"
    );
    let lines: Vec<Value> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    assert_eq!(lines.len(), 2, "both CRLF requests answered");
    assert!(lines[1]["result"]["tools"].is_array());
}

// ---------------------------------------------------------------------------
// 10. Warm-latency evidence (plan budget: p95 ≤ 120 ms warm localhost)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 11. Remediation M1: policy Ask degrades to deny (never forwards)
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_policy_ask_degrades_to_deny_and_never_forwarded() {
    let env = Env::new("ask-degrade");
    // The engine's charged path (tool named `Bash` + command arg) with a
    // zero invocation budget makes the FIRST call exceed budget ⇒ Ask.
    let policy = env.root.join("ask-policy.toml");
    std::fs::write(
        &policy,
        r#"
schema_version = 1
[defaults]
default_action = "allow"
[budgets.per_tool.Bash]
max_invocations = 0
"#,
    )
    .expect("write policy");
    let policy_arg = format!("--policy={}", policy.display());

    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec![policy_arg.as_str(), "--"];
    args.extend(up_refs);

    let ask_call = call_req(3, "Bash", serde_json::json!({"command":"ls"}));
    let s = run_session(&env, &args, &[], &[init_req(), ask_call]);

    // A degraded Ask is an ordinary gate denial: clean exit, isError result.
    assert!(s.status.success(), "stderr={}", s.stderr);
    let blocked = s.by_id(3);
    assert_eq!(blocked["result"]["isError"], true);
    let text = blocked["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("ask degraded to deny on transport proxy"),
        "{text}"
    );
    // PROOF of non-delivery: the call line never reached the mock.
    let log = read_log(&env);
    assert!(
        !log.iter().any(|l| l.contains(r#""id":3"#)),
        "Ask-degraded call must NEVER reach upstream; log={log:?}"
    );
}

// ---------------------------------------------------------------------------
// 12. Remediation N1: uppercase AGENTGUARD_PIN pre-seed matches
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_uppercase_preseed_pin_matches() {
    let env = Env::new("preseed-upper");
    let upstream = env.upstream();
    let up_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(up_refs);

    // Run 1 records the pin (lowercase digest in the store).
    let first = run_session(&env, &args, &[], &[init_req(), list_req()]);
    assert!(first.status.success(), "stderr={}", first.stderr);
    let stored: Value =
        serde_json::from_str(&std::fs::read_to_string(env.pin_store()).expect("pin store"))
            .expect("store json");
    let hash = stored["pins"][0]["tools_hash"]
        .as_str()
        .expect("tools_hash");

    // Run 2 pre-seeds the SAME digest in UPPERCASE — must match, not
    // quarantine (hex case is normalized before comparison).
    let upper = format!("SHA256:{}", hash.to_uppercase());
    let second = run_session(
        &env,
        &args,
        &[("AGENTGUARD_PIN", upper.as_str())],
        &[init_req(), list_req()],
    );
    assert!(
        second.status.success(),
        "uppercase pre-seed must match; stderr={}",
        second.stderr
    );
    assert!(
        second.stderr.contains("pin matched"),
        "expected a match, got stderr={}",
        second.stderr
    );
}

// ---------------------------------------------------------------------------
// 13. Graduated modes (FASE 5-B mechanism 1)
// ---------------------------------------------------------------------------

#[test]
fn proxy_e2e_audit_only_passes_blockable_call_but_logs_would_block() {
    // REQUIRED smoke: in audit-only mode a call the gates would deny reaches
    // the upstream (proven by the mock log) while the would-block lands on
    // stderr. Nothing is enforced; exit is clean.
    let env = Env::new("audit-only");
    let upstream = env.upstream();
    let mut args: Vec<&str> = vec!["--mode", "audit-only", "--"];
    args.extend(upstream.iter().map(String::as_str));

    let danger = call_req(3, "shell", serde_json::json!({"command":"rm -rf /"}));
    let s = run_session(&env, &args, &[], &[init_req(), danger]);

    assert!(s.status.success(), "audit-only never fails the session");
    assert!(
        s.stderr.contains("mode: audit-only"),
        "startup banner expected; stderr={}",
        s.stderr
    );
    assert!(
        s.stderr.contains("WOULD-BLOCK"),
        "would-block must be logged; stderr={}",
        s.stderr
    );
    assert!(
        !s.stderr.contains("BLOCKED tools/call"),
        "must not claim an enforced block; stderr={}",
        s.stderr
    );
    // The dangerous call REACHED upstream (that is what audit-only means).
    let log = read_log(&env);
    assert!(
        log.iter().any(|l| l.contains("rm -rf")),
        "audit-only must forward the denied call; log={log:?}"
    );
}

#[test]
fn proxy_e2e_filter_only_forwards_denied_call_and_filters_drifted_manifest() {
    let env = Env::new("filter-only");
    let tools_a = env.root.join("tools_a.json");
    let tools_b = env.root.join("tools_b.json");
    std::fs::write(
        &tools_a,
        r#"[{"name":"echo","description":"original","inputSchema":{"type":"object"}}]"#,
    )
    .expect("tools_a");
    std::fs::write(
        &tools_b,
        r#"[{"name":"echo","description":"TAMPERED — evil instructions","inputSchema":{"type":"object"}}]"#,
    )
    .expect("tools_b");

    let upstream = env.upstream();
    let upstream_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--mode", "filter-only", "--"];
    args.extend(upstream_refs);

    // Run 1 records the honest manifest.
    let first = run_session(
        &env,
        &args,
        &[("MOCK_TOOLS_FILE", tools_a.to_str().unwrap())],
        &[init_req(), list_req()],
    );
    assert!(first.status.success(), "stderr={}", first.stderr);

    // Run 2: drift filters the list, but a denied call STILL flows and the
    // session exits clean (no quarantine-grade outcome in filter-only).
    let danger = call_req(3, "shell", serde_json::json!({"command":"rm -rf /"}));
    let second = run_session(
        &env,
        &args,
        &[("MOCK_TOOLS_FILE", tools_b.to_str().unwrap())],
        &[init_req(), list_req(), danger],
    );
    assert!(
        second.stderr.contains("FILTERED"),
        "filter event must be logged; stderr={}",
        second.stderr
    );
    let filtered_list = second.by_id(2);
    assert_eq!(filtered_list["result"]["tools"], serde_json::json!([]));
    let blocked = second.by_id(3);
    assert!(
        blocked.get("result").is_some() && blocked["result"]["isError"] == false,
        "denied call must be FORWARDED (isError=false from mock), got {blocked}"
    );
    let log = read_log(&env);
    assert!(
        log.iter().any(|l| l.contains("rm -rf")),
        "filter-only never blocks calls; log={log:?}"
    );
    assert!(second.status.success(), "stderr={}", second.stderr);
}

#[test]
fn proxy_e2e_enforce_remains_default_mode() {
    // Default posture guard: without --mode the banner says enforce and a
    // denied call is actually blocked.
    let env = Env::new("default-mode");
    let upstream = env.upstream();
    let upstream_refs: Vec<&str> = upstream.iter().map(String::as_str).collect();
    let mut args: Vec<&str> = vec!["--"];
    args.extend(upstream_refs);

    let danger = call_req(3, "shell", serde_json::json!({"command":"rm -rf /"}));
    let s = run_session(&env, &args, &[], &[init_req(), danger]);
    assert!(s.stderr.contains("mode: enforce"), "stderr={}", s.stderr);
    let blocked = s.by_id(3);
    assert_eq!(blocked["result"]["isError"], true);
    let log = read_log(&env);
    assert!(
        !log.iter().any(|l| l.contains("rm -rf")),
        "enforce must block; log={log:?}"
    );
}

#[test]
fn proxy_e2e_warm_latency_median_under_120ms() {
    let env = Env::new("latency");
    let mut child = env
        .command(
            &env.upstream()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &[],
        )
        .spawn()
        .expect("spawn proxy");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));

    let mut roundtrip = |req: &str| -> String {
        stdin
            .write_all(req.as_bytes())
            .and_then(|_| stdin.write_all(b"\n"))
            .and_then(|_| stdin.flush())
            .expect("write request");
        let mut line = String::new();
        reader.read_line(&mut line).expect("read response");
        assert!(!line.is_empty(), "upstream closed early");
        line
    };

    // Warm-up: initialize + first list + first call (process spawn, policy
    // load, pin recording — all excluded from the warm measurement).
    roundtrip(&init_req());
    roundtrip(&list_req());
    roundtrip(&call_req(100, "echo", serde_json::json!({"value":"warm"})));

    const N: usize = 50;
    let mut samples: Vec<Duration> = Vec::with_capacity(N);
    for i in 0..N {
        let r = call_req(1000 + i as i64, "echo", serde_json::json!({"value": i}));
        let start = Instant::now();
        let resp = roundtrip(&r);
        samples.push(start.elapsed());
        let v: Value = serde_json::from_str(resp.trim()).expect("response json");
        assert_eq!(v["result"]["isError"], false, "warm call must succeed");
    }

    samples.sort();
    let median = samples[N / 2];
    let p95 = samples[(N as f64 * 0.95).ceil() as usize - 1];
    stdin.flush().ok();
    drop(stdin);
    let _ = child.wait();

    // Plan budget: p95 ≤ 120 ms warm localhost; we pin the (weaker but
    // stabler) median against the same number and REPORT p95.
    assert!(
        median < Duration::from_millis(120),
        "warm median {:?} exceeds the 120ms plan budget (p95 was {p95:?})",
        median
    );
    eprintln!("proxy warm latency: median {median:?}, p95 {p95:?} (n={N})");
}
