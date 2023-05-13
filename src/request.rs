use crate::response::ResponseBody;
use crate::service::Service;
use std::time::Duration;
use ureq::Agent;
use warp::http::Response;
use warp::hyper;
use warp::Reply;

#[derive(Debug, Clone)]
pub struct RequestService {
    pub agent: Agent,
    pub svc: Service,
}

impl RequestService {
    pub fn new(svc: Service) -> RequestService {
        let agent: Agent = ureq::AgentBuilder::new()
            .timeout_read(Duration::from_secs(5))
            .timeout_write(Duration::from_secs(5))
            .build();

        RequestService { agent, svc }
    }
    /// handle response varients
    /// specified errors from backend will be passed along as is
    /// network and decoding errors will reject with 404
    fn handle_response(
        result: Result<ureq::Response, ureq::Error>,
    ) -> Result<Response<String>, warp::Rejection> {
        match result {
            Ok(resp) => {
                let status = resp.status();
                if let Ok(s) = resp.into_string() {
                    Response::builder()
                        .status(status)
                        .body(s)
                        .map_err(|_| warp::reject::not_found())
                } else {
                    // if response cannot be decoded
                    // to string reject with 404
                    Err(warp::reject::not_found())
                }
            }
            Err(ureq::Error::Status(code, resp)) => {
                if let Ok(s) = resp.into_string() {
                    Response::builder()
                        .status(code)
                        .body(s)
                        .map_err(|_| warp::reject::not_found())
                } else {
                    // if response cannot be decoded
                    // to string reject with 404
                    Err(warp::reject::not_found())
                }
            }
            Err(_) => {
                // any network errors will be 404s
                Err(warp::reject::not_found())
            }
        }
    }

    pub async fn post(
        self,
        req_uri: &str,
        bytes: bytes::Bytes,
    ) -> Result<Response<String>, warp::Rejection> {
        let resp = self
            .agent
            .post(req_uri)
            .set("Content-Type", "application/octet-stream")
            .set("Accept-Encoding", "gzip,deflate")
            .set("X-Forwarded-Proto", "https")
            .set("X-Forwarded-Host", self.svc.config.forwarded_for.as_str())
            .send_bytes(&bytes);

        RequestService::handle_response(resp)
    }
    pub async fn fetch(self, req_uri: &str) -> Result<impl Reply, warp::Rejection> {
        let resp = self
            .agent
            .get(req_uri)
            .set("X-Forwarded-Proto", "https")
            .set("X-Forwarded-Host", self.svc.config.forwarded_for.as_str())
            .call();

        RequestService::handle_response(resp)
    }
    pub async fn decode(reply: impl warp::Reply) -> Result<impl Reply, warp::Rejection> {
        let (parts, body) = reply.into_response().into_parts();
        let bytes = hyper::body::to_bytes(body).await.unwrap();
        let s = String::from_utf8(bytes.into_iter().collect()).unwrap();
        if let Ok(decoded) = ResponseBody::decode_data(&s) {
            let resp = Response::from_parts(parts, decoded);
            Ok(resp)
        } else {
            // any errors in base64 data decode will
            // bubble up here and result in a 404
            Err(warp::reject::not_found())
        }
    }

    pub fn req_target(path: &str, method: Option<&str>) -> String {
        let method = method.unwrap_or("get");
        [method, " ", path].concat()
    }
}
