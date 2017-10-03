extern crate hyper;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate env_logger;
extern crate hyper_tls;
extern crate hex;
extern crate futures;
extern crate tokio_core;
#[macro_use]
extern crate error_chain;
extern crate ring;
extern crate docopt;
extern crate base64;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::rc::Rc;
use std::str;

use docopt::Docopt;
use error_chain::ChainedError;
use futures::future;
use futures::prelude::*;
use hex::FromHex;
use hyper::client::HttpConnector;
use hyper::server::{Http, Service, Request, Response};
use hyper::{Post, StatusCode, Client, Method};
use hyper_tls::HttpsConnector;
use ring::digest::SHA1;
use ring::hmac;
use tokio_core::net::TcpListener;
use tokio_core::reactor::Core;

// Write the Docopt usage string.
const USAGE: &'static str = "
Usage: eeyore [options]

Options:
    -u, --username VAL  GitHub username
    -p, --password VAL  GitHub password
    -a, --addr VAL      address to bind to
    -k, --key VAL       webhook secret
";
const BOT: &str = "alexcrichton";

use errors::*;

mod errors {
    use futures::prelude::*;

    error_chain! {}

    pub type MyFuture<T> = Box<Future<Item = T, Error = Error>>;
}

#[derive(Clone)]
struct Eeyore {
    client: Client<HttpsConnector<HttpConnector>>,
    key: Option<Rc<hmac::VerificationKey>>,
    auth: String,
}

impl Service for Eeyore {
    type Request = Request;
    type Response = Response;
    type Error = hyper::Error;
    type Future = Box<Future<Item=Response, Error=hyper::Error>>;

    fn call(&self, req: Request) -> Self::Future {
        match (req.method(), req.path()) {
            (&Post, "/webhook") => {
                Box::new(self.webhook(req).then(|response| {
                    match response {
                        Ok(()) => Ok(Response::new()),
                        Err(e) => {
                            debug!("error: {}", e.display_chain());
                            Err(hyper::Error::Status)
                        }
                    }
                }))
            },
            _ => {
                Box::new(future::ok(Response::new()
                    .with_status(StatusCode::NotFound)))
            }
        }
    }
}

impl Eeyore {
    fn webhook(&self, req: Request) -> MyFuture<()> {
        let n = match Notification::from(&req) {
            Ok(n) => n,
            Err(e) => return Box::new(future::err(e)),
        };
        debug!("id: {}, event: {}", n.id, n.event);
        let me = self.clone();
        let body = req.body()
            .concat2()
            .map_err(|_| Error::from("failed to read body"))
            .and_then(move |body| {
                let body = str::from_utf8(&body)
                    .map_err(|_| "invalid utf-8 body")?;
                if let Some(ref key) = me.key {
                    n.verify(key, &body)?;
                }
                Ok((n, body.to_string()))
            });

        let me = self.clone();
        Box::new(body.and_then(move |(n, body)| {
            me.respond(n, body)
        }))
    }

    fn respond(&self, n: Notification, body: String) -> MyFuture<()> {
        if n.event != "issue_comment" {
            return Box::new(future::ok(()))
        }
        let comment = serde_json::from_str(&body)
            .chain_err(|| "failed to parse json");
        let comment: IssueComment = match comment {
            Ok(n) => n,
            Err(e) => return Box::new(future::err(e)),
        };
        if comment.action != "created" {
            debug!("skipping action {}", comment.action);
            return Box::new(future::ok(()))
        }
        let mut added = HashSet::new();
        let mut removed = HashSet::new();
        let mut errors = Vec::new();
        let prefix = format!("@{}", BOT);
        for line in comment.comment.body.lines() {
            if !line.starts_with(&prefix) {
                continue
            }
            for part in line.split_whitespace().skip(1) {
                if part.starts_with("+") {
                    added.insert(part[1..].to_string());
                } else if part.starts_with("-") {
                    removed.insert(part[1..].to_string());
                } else {
                    errors.push(part.to_string());
                }
            }
        }

        let mut futures: Vec<MyFuture<_>> = Vec::new();
        for label in added {
            let get = format!("{}/labels/{}", comment.issue.repository_url, label);
            let is_valid_label = self.get(&get);
            let url = format!("{}/labels", comment.issue.url);
            let payload = serde_json::to_string(&[&label]).unwrap();
            let me = self.clone();
            futures.push(Box::new(is_valid_label.and_then(move |_| {
                me.post(&url, payload)
            }).then(move |result| {
                match result {
                    Ok(()) => Ok(None),
                    Err(e) => {
                        debug!("failed due to {}", e.display_chain());
                        Ok(Some(format!("failed to add label: {}", label)))
                    }
                }
            })));
        }
        for label in removed {
            let url = format!("{}/labels/{}", comment.issue.url, label);
            futures.push(Box::new(self.delete(&url).then(move |result| {
                match result {
                    Ok(()) => Ok(None),
                    Err(e) => {
                        debug!("failed due to {}", e.display_chain());
                        Ok(Some(format!("failed to remove label: {}", label)))
                    }
                }
            })));
        }

        let me = self.clone();
        Box::new(future::join_all(futures).and_then(move |results| -> MyFuture<_> {
            let api_errors = results.into_iter()
                .filter_map(|x| x)
                .collect::<Vec<_>>();
            let errors = errors.iter()
                .map(|e| format!("unknown command: \"{}\"", e))
                .chain(api_errors)
                .collect::<Vec<_>>();
            if errors.len() == 0 {
                return Box::new(future::ok(()))
            }

            let mut body = format!("errors:\n\n");
            for error in errors {
                body.push_str(&format!("* {}\n", error));
            }

            let url = format!("{}/comments", comment.issue.url);
            #[derive(Serialize)]
            struct NewComment { body: String }
            let body = serde_json::to_string(&NewComment {
                body: body,
            }).unwrap();
            me.post(&url, body)
        }))
    }

    fn get(&self, uri: &str) -> MyFuture<()> {
        self.req(uri, Method::Get, None)
    }

    fn post(&self, uri: &str, body: String) -> MyFuture<()> {
        self.req(uri, Post, Some(body))
    }

    fn delete(&self, uri: &str) -> MyFuture<()> {
        self.req(uri, Method::Delete, None)
    }

    fn req(&self, uri: &str, method: Method, body: Option<String>) -> MyFuture<()> {
        let mut req = Request::new(method, uri.parse().unwrap());
        req.headers_mut().set_raw("User-Agent", "Eeyore");
        req.headers_mut().set_raw("Accept", "application/vnd.github.v3+json");
        if let Some(body) = body {
            req.headers_mut().set_raw("Content-Type", "application/json");
            req.headers_mut().set_raw("Content-Length", body.len().to_string());
            req.set_body(hyper::Body::from(body.into_bytes()));
        }
        let auth = format!("basic {}", self.auth);
        req.headers_mut().set_raw("Authorization", auth);
        let uri = uri.to_string();
        Box::new(self.client.request(req).then(move |resp| {
            debug!("finished: {}", uri);
            let resp = resp.chain_err(|| "failed to do http")?;
            if resp.status().is_success() {
                return Ok(())
            }
            Err(format!("failed response\n\
                status: {}\n\
                headers: {:?}\n\
            ", resp.status(), resp.headers()).into())
        }))
    }
}

#[derive(Deserialize)]
struct IssueComment {
    action: String,
    issue: Issue,
    comment: Comment,
}

#[derive(Deserialize)]
struct Issue {
    // id: u32,
    // number: u32,
    url: String,
    repository_url: String,
}

#[derive(Deserialize)]
struct Comment {
    // id: u32,
    body: String,
    // url: String,
}

struct Notification {
    id: String,
    event: String,
    signature: String,
}

impl Notification {
    fn from(req: &Request) -> Result<Notification> {
        let get = |name: &str| -> Result<_> {
            req.headers()
                .get_raw(name)
                .and_then(|n| n.one())
                .and_then(|n| str::from_utf8(n).ok())
                .ok_or_else(|| format!("missing header {}", name).into())
        };
        let ua = get("User-Agent")?;
        if !ua.starts_with("GitHub-Hookshot/") {
            bail!("unknown user agent: {}", ua);
        }
        Ok(Notification {
            id: get("X-GitHub-Delivery")?.to_string(),
            event: get("X-GitHub-Event")?.to_string(),
            signature: get("X-Hub-Signature")?.to_string(),
        })
    }

    fn verify(&self, key: &hmac::VerificationKey, body: &str) -> Result<()> {
        if !self.signature.starts_with("sha1=") {
            return Err("not a sha1 sig".into())
        }
        let signature = &self.signature[5..];
        let signature: Vec<u8> = FromHex::from_hex(signature).map_err(|_| {
            "invalid hex in signature"
        })?;
        hmac::verify(&key, body.as_bytes(), &signature).map_err(|_| {
            "invalid hmac signature".into()
        })
    }
}

fn main() {
    env_logger::init().unwrap();

    let args = Docopt::new(USAGE).unwrap()
        .argv(std::env::args())
        .parse()
        .unwrap_or_else(|e| e.exit());

    let addr = args.get_str("--addr");
    let addr = if addr.len() > 0 {
        addr.parse::<SocketAddr>().unwrap()
    } else {
        "127.0.0.1:8080".parse().unwrap()
    };

    let key = args.get_str("--key");
    let key = if key.len() == 0 {
        None
    } else {
        Some(Rc::new(hmac::VerificationKey::new(&SHA1, key.as_bytes())))
    };

    let username = args.get_str("--username");
    let password = args.get_str("--password");
    let auth = format!("{}:{}", username, password);
    let auth = base64::encode(&auth);

    let mut core = Core::new().unwrap();
    let handle = core.handle();
    let socket = TcpListener::bind(&addr, &handle).unwrap();
    println!("Listening on: {}", addr);

    let client = Client::configure()
        .connector(hyper_tls::HttpsConnector::new(4, &handle).unwrap())
        .build(&handle);

    let proto = Http::new();
    let srv = socket.incoming().for_each(move |(socket, addr)| {
        proto.bind_connection(&handle, socket, addr, Eeyore {
            client: client.clone(),
            key: key.clone(),
            auth: auth.clone(),
        });
        Ok(())
    });
    core.run(srv).unwrap();
}
