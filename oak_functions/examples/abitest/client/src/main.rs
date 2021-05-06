//
// Copyright 2021 The Project Oak Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

//! Oak Functions ABI test client.

use anyhow::Context;
use hyper::Client;
use oak_functions_abitest_common::*;
use structopt::StructOpt;

#[derive(StructOpt, Clone)]
#[structopt(about = "HTTPS server pseudo-Node Client Example.")]
pub struct Opt {
    #[structopt(
        long,
        help = "URI of the application to connect to",
        default_value = "http://localhost:8080/invoke"
    )]
    uri: String,
}

type TestFn = fn(&str) -> anyhow::Result<()>;

struct Test {
    name: String,
    expected_response: String,
}

impl Test {
    fn new(name: &str, expected_response: &str) -> Self {
        Self {
            name: name.to_string(),
            expected_response: expected_response.to_string(),
        }
    }
}

struct TestManager {
    uri: String,
    tests: Vec<Test>,
}

impl TestManager {
    fn new(uri: &str) -> Self {
        let mut tests = vec![];
        tests.push(Test::new(TEST_READ_WRITE, TEST_READ_WRITE_RESPONSE));

        Self {
            uri: uri.to_string(),
            tests,
        }
    }

    async fn run_tests(&self) -> anyhow::Result<()> {
        for test in &self.tests {
            self
                .run_test(&test.name, &test.expected_response)
                .await
                .context(format!("Couldn't run test: {}", &test.name))?;
        }
        Ok(())
    }

    async fn run_test(&self, test_name: &str, expected_response: &str) -> anyhow::Result<()> {

        Ok(())
    }
}

async fn send_request(
    // client: &hyper::client::Client<
    //     hyper_rustls::HttpsConnector<hyper::client::HttpConnector>,
    //     hyper::Body,
    // >,
    uri: &str,
    body: &str,
) {
    // let client = Client::new();

    let mut http = hyper::client::HttpConnector::new();
    // Enable HTTPS by allowing Uri`s to have the `https` scheme.
    // http.enforce_http(false);
    let client: hyper::client::Client<_, hyper::Body> =
        hyper::client::Client::builder().build(http);

    let request = hyper::Request::builder()
        .method(http::Method::POST)
        .uri(uri)
        .body(body)
        .expect("Couldn't create HTTP request");

    let response = client
        .request(request.to_string())
        .await
        .expect("Couldn't send request");

    assert_eq!(response.status(), http::StatusCode::OK);

    // log::info!("response: {:?}", resp);
    // log::info!(
    //     "response body: {:?}",
    //     hyper::body::to_bytes(resp.into_body())
    //         .await
    //         .expect("could not read response body")
    // );
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let opt = Opt::from_args();

    // let key_pair = oak_sign::KeyPair::generate()?;
    // let signature =
    //     oak_sign::SignatureBundle::create(oak_abi::OAK_CHALLENGE.as_bytes(), &key_pair)?;

    // let path = &opt.ca_cert_path;
    // let ca_file = fs::File::open(path).unwrap_or_else(|e| panic!("failed to open {}: {}", path, e));
    // let mut ca = io::BufReader::new(ca_file);

    // // Build an HTTP connector which supports HTTPS too.
    // let mut http = hyper::client::HttpConnector::new();
    // http.enforce_http(false);
    // // Build a TLS client, using the custom CA store for lookups.
    // let mut tls = rustls::ClientConfig::new();
    // tls.root_store
    //     .add_pem_file(&mut ca)
    //     .expect("failed to load custom CA store");
    // // Join the above part into an HTTPS connector.
    // let https = hyper_rustls::HttpsConnector::from((http, tls));

    // let client: hyper::client::Client<_, hyper::Body> =
    //     hyper::client::Client::builder().build(https);

    // check_endpoint(
    //     &client,
    //     "http://localhost:8080/invoke",
    //     &Label::public_untrusted(),
    //     serde_json::to_string(&signature).unwrap(),
    // )
    // .await;

    // check_endpoint(
    //     &client,
    //     "https://localhost:8081",
    //     &confidentiality_label(tls_endpoint_tag("localhost:8080")),
    //     serde_json::to_string(&signature).unwrap(),
    // )
    // .await;

    let test_manager = TestManager::new(&opt.uri);
    test_manager.run_tests().await.context("Couldn't run tests")?;

    Ok(())
}
