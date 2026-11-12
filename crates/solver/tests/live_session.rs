use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use akamai_solver::{AkamaiClient, Profile, SolveOptions, solve};

#[derive(Debug)]
struct Request {
    path: String,
    headers: String,
    body: String,
}

fn read_request(stream: &mut TcpStream) -> Option<Request> {
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let boundary = loop {
        let count = match stream.read(&mut chunk) {
            Ok(0) if bytes.is_empty() => return None,
            Ok(count) => count,
            Err(error)
                if bytes.is_empty()
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                return None;
            }
            Err(error) => panic!("fixture request read failed: {error}"),
        };
        assert_ne!(count, 0, "connection closed during headers");
        bytes.extend_from_slice(&chunk[..count]);
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = String::from_utf8(bytes[..boundary].to_vec()).unwrap();
    let length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while bytes.len() < boundary + length {
        let count = stream.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "connection closed before body");
        bytes.extend_from_slice(&chunk[..count]);
    }
    Some(Request {
        path: headers
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .to_owned(),
        headers,
        body: String::from_utf8(bytes[boundary..boundary + length].to_vec()).unwrap(),
    })
}

#[tokio::test(flavor = "current_thread")]
async fn live_responses_drive_cookie_dependent_posts_and_unlock_local_route() {
    const SCRIPT_WITH_S8: &str = "const bmak = {}; s8=fA(G9,[['CAr3qAAAAAA','C','r5','b3Mrf','C5rCrbM5r3qAAAAAA','C595bbf','9f99bAMqAAAAAA','f5','b33f3qAAAAAA','9999999','bC3f9rI','IA5C','5AC9','fbAA','CArb','9Ir5','Ibf9C','f5Mb9','IfIAM5','5','I3','I5AA','IAAA'],0]);";
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Request>::new()));
    let captured = records.clone();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let mut workers = Vec::new();
        while captured.lock().unwrap().len() < 8 && start.elapsed() < Duration::from_secs(10) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let captured = Arc::clone(&captured);
            workers.push(thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else { return };
                let mut records = captured.lock().unwrap();
                let posts = records
                    .iter()
                    .filter(|r| r.path == "/a/b/c/d" && !r.body.is_empty())
                    .count()
                    + usize::from(request.path == "/a/b/c/d" && !request.body.is_empty());
                let (status, extra, body) = match request.path.as_str() {
                    "/" if posts < 3 => (
                        "403 Forbidden",
                        "Set-Cookie: bm_sz=tok~blob~4100000~1; Path=/\r\nSet-Cookie: secret=hidden; HttpOnly; Path=/\r\n".to_owned(),
                        "<html><script src=\"/a/b/c/d\"></script></html>".to_owned(),
                    ),
                    "/a/b/c/d" if request.body.is_empty() => (
                        "200 OK",
                        String::new(),
                        SCRIPT_WITH_S8.to_owned(),
                    ),
                    "/a/b/c/d" => {
                        let state = if posts == 3 {
                            "fixture~0~validated"
                        } else {
                            "fixture~-1~pending"
                        };
                        let next_seed = 4_100_000 + (posts as u32) * 1_000;
                        (
                            "202 Accepted",
                            format!(
                                "Set-Cookie: step={posts}; Path=/\r\nSet-Cookie: bm_sz=tok~blob~{next_seed}~1; Path=/\r\nSet-Cookie: _abck={state}; Path=/\r\n"
                            ),
                            format!("{{\"step\":{posts}}}"),
                        )
                    }
                    "/" => ("200 OK", String::new(), "local protected response".to_owned()),
                    "/search" => (
                        "200 OK",
                        String::new(),
                        "<html><body>iPhone 17 Pro $999.99</body></html>".to_owned(),
                    ),
                    "/graphql" => {
                        assert!(request.body.contains("CartQuery"));
                        assert!(
                            request
                                .headers
                                .to_ascii_lowercase()
                                .contains("content-type: application/json")
                        );
                        assert!(request.headers.to_ascii_lowercase().contains("step=3"));
                        (
                            "200 OK",
                            String::new(),
                            "{\"data\":{\"customer\":{\"cart\":{\"totalQuantity\":0}}}}".to_owned(),
                        )
                    }
                    other => panic!("unexpected fixture path: {other}"),
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).unwrap();
                records.push(request);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(captured.lock().unwrap().len(), 8);
    });
    let mut client = AkamaiClient::builder()
        .profile(Profile::Chrome154)
        .posts(3)
        .build()
        .unwrap();
    let result = client.solve(&format!("http://{address}/")).await.unwrap();
    let search = client
        .get(&format!("http://{address}/search"))
        .await
        .unwrap();
    let gql = client
        .post_json(
            &format!("http://{address}/graphql"),
            &serde_json::json!({
                "operationName": "CartQuery",
                "query": "query CartQuery { customer { cart { totalQuantity } } }",
                "variables": {}
            }),
        )
        .await
        .unwrap();
    server.join().unwrap();
    assert_eq!(result.page_status, 403);
    assert_eq!(result.post_status, Some(202));
    assert_eq!(result.payloads_posted, 3);
    assert_eq!(result.verify_status, Some(200));
    assert_eq!(result.abck_after.as_deref(), Some("fixture~0~validated"));
    assert!(search.text().contains("iPhone 17 Pro $999.99"));
    assert_eq!(
        gql.text(),
        "{\"data\":{\"customer\":{\"cart\":{\"totalQuantity\":0}}}}"
    );

    let records = records.lock().unwrap();
    let posts: Vec<_> = records
        .iter()
        .filter(|r| r.path == "/a/b/c/d" && !r.body.is_empty())
        .collect();
    assert_eq!(posts.len(), 3);
    let seeds: Vec<String> = posts
        .iter()
        .map(|r| {
            let outer: serde_json::Value = serde_json::from_str(&r.body).unwrap();
            let env =
                akamai_codec::sensor::Envelope::parse(outer["sensor_data"].as_str().unwrap(), 0)
                    .unwrap();
            env.header[4].clone()
        })
        .collect();
    assert_eq!(seeds, vec!["4100000", "4101000", "4102000"]);
    for request in posts {
        let headers = request.headers.to_ascii_lowercase();
        assert!(headers.contains("secret=hidden"));
        assert!(headers.contains("priority: u=1, i"));
        assert!(headers.contains("sec-fetch-mode: cors"));
    }
}

async fn run_sbsd_scenario(
    script_path: &'static str,
    post_path: &'static str,
    expected_posts: usize,
) -> (akamai_solver::SolveOutcome, Vec<Request>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Request>::new()));
    let captured = records.clone();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let mut workers = Vec::new();
        while captured.lock().unwrap().len() < expected_posts + 3
            && start.elapsed() < Duration::from_secs(10)
        {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let captured = Arc::clone(&captured);
            workers.push(thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else { return };
                let mut records = captured.lock().unwrap();
                let validated = records
                    .iter()
                    .any(|r| r.path == post_path && !r.body.is_empty());
                let (status, extra, body) = match request.path.as_str() {
                    "/" if !validated => (
                        "403 Forbidden",
                        "Set-Cookie: sbsd_o=seed-0; Path=/\r\n".to_owned(),
                        format!("<html><script src=\"{script_path}\"></script></html>"),
                    ),
                    path if path == script_path && request.body.is_empty() => {
                        ("200 OK", String::new(), "/* sbsd */".to_owned())
                    }
                    path if path == post_path && !request.body.is_empty() => (
                        "202 Accepted",
                        "Set-Cookie: _abck=fixture~0~validated; Path=/\r\nSet-Cookie: sbsd=validated; Path=/\r\n".to_owned(),
                        "{\"ok\":true}".to_owned(),
                    ),
                    "/" => ("200 OK", String::new(), "protected".to_owned()),
                    other => panic!("unexpected fixture path: {other}"),
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).unwrap();
                records.push(request);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(captured.lock().unwrap().len(), expected_posts + 3);
    });
    let mut options = SolveOptions::new(format!("http://{address}/"));
    options.posts = 1;
    let result = solve(options).await.unwrap();
    server.join().unwrap();
    let records = Arc::try_unwrap(records).unwrap().into_inner().unwrap();
    (result, records)
}

#[tokio::test(flavor = "current_thread")]
async fn passive_sbsd_posts_two_json_body_payloads() {
    let (result, records) = run_sbsd_scenario(
        "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?v=f96b0144-83cf-fd90-7200-553b2f046010",
        "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj",
        2,
    )
    .await;
    assert_eq!(result.payloads_posted, 2);
    assert_eq!(result.post_status, Some(202));
    assert_eq!(result.verify_status, Some(200));
    assert_eq!(
        result.cookies.get("sbsd").map(String::as_str),
        Some("validated")
    );
    let posts: Vec<_> = records
        .iter()
        .filter(|r| r.path == "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj" && !r.body.is_empty())
        .collect();
    assert_eq!(posts.len(), 2);
    assert_ne!(posts[0].body, posts[1].body);
    for state in posts {
        let parsed: serde_json::Value = serde_json::from_str(&state.body).unwrap();
        assert!(parsed["body"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(
            state
                .headers
                .to_ascii_lowercase()
                .contains("content-type: application/json")
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn active_sbsd_posts_one_payload_to_the_t_challenge() {
    let (result, records) = run_sbsd_scenario(
        "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?v=f96b0144-83cf-fd90-7200-553b2f046010&t=183446612",
        "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?t=183446612",
        1,
    )
    .await;
    assert_eq!(result.payloads_posted, 1);
    assert_eq!(result.post_status, Some(202));
    assert_eq!(result.verify_status, Some(200));
    assert_eq!(
        records
            .iter()
            .filter(
                |r| r.path == "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?t=183446612"
                    && !r.body.is_empty()
            )
            .count(),
        1
    );
}

#[tokio::test(flavor = "current_thread")]
async fn sdk_client_persists_validated_session_across_get_and_post_json() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Request>::new()));
    let captured = records.clone();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let mut workers = Vec::new();
        while captured.lock().unwrap().len() < 6 && start.elapsed() < Duration::from_secs(10) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let captured = Arc::clone(&captured);
            workers.push(thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else { return };
                let mut records = captured.lock().unwrap();
                let validated = records
                    .iter()
                    .any(|r| r.path == "/a/b/c/d" && !r.body.is_empty());
                let (status, extra, body) = match request.path.as_str() {
                    "/" if !validated => (
                        "403 Forbidden",
                        "Set-Cookie: _abck=fixture~-1~pending; Path=/\r\n".to_owned(),
                        "<html><script src=\"/a/b/c/d\"></script></html>".to_owned(),
                    ),
                    "/a/b/c/d" if request.body.is_empty() => (
                        "200 OK",
                        String::new(),
                        "const bmak = {};".to_owned(),
                    ),
                    "/a/b/c/d" => (
                        "201 Created",
                        "Set-Cookie: _abck=fixture~0~validated; Path=/\r\n".to_owned(),
                        "{\"success\":true}".to_owned(),
                    ),
                    "/" => ("200 OK", String::new(), "home".to_owned()),
                    "/catalog" => (
                        "200 OK",
                        "Content-Type: application/json\r\n".to_owned(),
                        "{\"sku\":\"6443166\"}".to_owned(),
                    ),
                    "/graphql" => (
                        "200 OK",
                        "Content-Type: application/json\r\n".to_owned(),
                        format!("{{\"echo\":{}}}", request.body),
                    ),
                    other => panic!("unexpected fixture path: {other}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                    body.len()
                )
                .unwrap();
                records.push(request);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });
    let base = format!("http://{address}/");
    let mut client = AkamaiClient::builder()
        .profile(Profile::Chrome154)
        .posts(1)
        .build()
        .unwrap();
    let outcome = client.solve(&base).await.unwrap();
    assert!(outcome.abck_advanced());
    assert!(client.is_validated(&base).unwrap());
    let catalog = client
        .get(&format!("http://{address}/catalog"))
        .await
        .unwrap();
    let catalog_json: serde_json::Value = catalog.json().unwrap();
    assert_eq!(catalog_json["sku"], "6443166");
    let gql = client
        .post_json(
            &format!("http://{address}/graphql"),
            &serde_json::json!({"operationName":"CartQuery"}),
        )
        .await
        .unwrap();
    let gql_json: serde_json::Value = gql.json().unwrap();
    assert_eq!(gql_json["echo"]["operationName"], "CartQuery");
    server.join().unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn sdk_repeats_sbsd_with_updated_state_on_every_page() {
    const SCRIPT_PATH: &str =
        "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj?v=f96b0144-83cf-fd90-7200-553b2f046010";
    const POST_PATH: &str = "/rQ2v9Lk/Tp/8HcW1Zm/f3NxYd0K/aG7Bu/sE/4Vj";

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Request>::new()));
    let captured = records.clone();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let mut workers = Vec::new();
        while captured.lock().unwrap().len() < 10 && start.elapsed() < Duration::from_secs(10) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let captured = Arc::clone(&captured);
            workers.push(thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else { return };
                let mut records = captured.lock().unwrap();
                let state_posts = records
                    .iter()
                    .filter(|r| r.path == POST_PATH && !r.body.is_empty())
                    .count();
                let challenge = format!("<html><script src=\"{SCRIPT_PATH}\"></script></html>");
                let (status, extra, body) = match request.path.as_str() {
                    "/one" if state_posts < 2 => (
                        "403 Forbidden",
                        "Set-Cookie: sbsd_o=state-0; Path=/\r\n".to_owned(),
                        challenge,
                    ),
                    "/two" if state_posts < 4 => ("403 Forbidden", String::new(), challenge),
                    path if path == SCRIPT_PATH && request.body.is_empty() => {
                        ("200 OK", String::new(), "/* sbsd */".to_owned())
                    }
                    path if path == POST_PATH && !request.body.is_empty() => (
                        "202 Accepted",
                        format!("Set-Cookie: sbsd_o=state-{}; Path=/\r\n", state_posts + 1),
                        "{\"ok\":true}".to_owned(),
                    ),
                    "/one" => ("200 OK", String::new(), "one".to_owned()),
                    "/two" => ("200 OK", String::new(), "two".to_owned()),
                    other => panic!("unexpected fixture path: {other}"),
                };
                write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}", body.len()).unwrap();
                records.push(request);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(captured.lock().unwrap().len(), 10);
    });

    let mut client = AkamaiClient::builder()
        .profile(Profile::Chrome154)
        .posts(1)
        .build()
        .unwrap();
    let first = client
        .solve(&format!("http://{address}/one"))
        .await
        .unwrap();
    let second = client
        .solve(&format!("http://{address}/two"))
        .await
        .unwrap();
    assert_eq!(first.payloads_posted, 2);
    assert_eq!(second.payloads_posted, 2);
    assert_eq!(first.verify_status, Some(200));
    assert_eq!(second.verify_status, Some(200));
    assert!(
        client
            .cookie_header(&format!("http://{address}/two"))
            .unwrap()
            .contains("sbsd_o=state-4")
    );
    server.join().unwrap();
    let records = Arc::try_unwrap(records).unwrap().into_inner().unwrap();
    let bodies: Vec<_> = records
        .iter()
        .filter(|r| r.path == POST_PATH && !r.body.is_empty())
        .map(|r| r.body.clone())
        .collect();
    assert_eq!(bodies.len(), 4);
    assert_ne!(bodies[0], bodies[2]);
}

#[tokio::test(flavor = "current_thread")]
async fn native_template_reencodes_sensor_payload_for_new_bm_sz_without_quickjs() {
    let plain = r#"{"ver":"tok123","fpt":"1","fpc":"2","sde":"0","hls":"0","pde":"0","pur":"http://old.test/","din":[{"ua":"Mozilla"},{"npl":5}],"mst":[{"kc":0},{"mc":1},{"tc":0}]}"#;
    let cipher = akamai_codec::sensor::encode_body(plain, ':', 4_000_000, 65_914);
    let captured = serde_json::json!({
        "sensor_data": format!("3;0;1;0;4000000;tok123;0,0,0,0,0,4;{cipher}")
    })
    .to_string();
    let template = akamai_codec::sensor::BuildTemplate::from_captured_posts(
        "sha".to_owned(),
        &[captured],
        4_000_000,
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let records = Arc::new(Mutex::new(Vec::<Request>::new()));
    let captured_reqs = records.clone();
    let server = thread::spawn(move || {
        let start = Instant::now();
        let mut workers = Vec::new();
        while captured_reqs.lock().unwrap().len() < 4 && start.elapsed() < Duration::from_secs(10) {
            let (mut stream, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                    continue;
                }
                Err(error) => panic!("fixture accept: {error}"),
            };
            let captured_reqs = Arc::clone(&captured_reqs);
            workers.push(thread::spawn(move || {
                let Some(request) = read_request(&mut stream) else { return };
                let mut records = captured_reqs.lock().unwrap();
                let validated = records.iter().any(|r| r.path == "/a/b/c/d" && r.body.contains("7777777"));
                let (status, extra, body) = match request.path.as_str() {
                    "/" if !validated => (
                        "200 OK",
                        "Set-Cookie: _abck=fixture~-1~pending; Path=/\r\nSet-Cookie: bm_sz=tok~blob~7777777~1; Path=/\r\n".to_owned(),
                        "<html><script src=\"/a/b/c/d\"></script></html>".to_owned(),
                    ),
                    "/a/b/c/d" if request.body.is_empty() => (
                        "200 OK",
                        String::new(),
                        "const bmak = {}; throw new Error('QuickJS should not run in native template mode');".to_owned(),
                    ),
                    "/a/b/c/d" => (
                        "201 Created",
                        "Set-Cookie: _abck=fixture~0~validated; Path=/\r\n".to_owned(),
                        "{\"success\":true}".to_owned(),
                    ),
                    "/" => ("200 OK", String::new(), "ok".to_owned()),
                    other => panic!("unexpected fixture path: {other}"),
                };
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
                    body.len()
                )
                .unwrap();
                records.push(request);
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
    });

    let page_url = format!("http://{address}/");
    let mut options = SolveOptions::new(&page_url);
    options.posts = 1;
    options.template = Some(template);
    let outcome = solve(options).await.unwrap();
    assert!(outcome.abck_advanced());
    server.join().unwrap();

    let records = Arc::try_unwrap(records).unwrap().into_inner().unwrap();
    let post = records
        .iter()
        .find(|r| r.path == "/a/b/c/d" && !r.body.is_empty())
        .unwrap();
    let outer: serde_json::Value = serde_json::from_str(&post.body).unwrap();
    let env =
        akamai_codec::sensor::Envelope::parse(outer["sensor_data"].as_str().unwrap(), 0).unwrap();
    assert_eq!(env.header[4], "7777777");
    let decoded = akamai_codec::sensor::decode_body(&env.ciphertext, ':', 7_777_777, Some(65_914));
    assert!(decoded.contains(&format!("\"pur\":\"{page_url}\"")));
}
