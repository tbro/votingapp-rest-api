# votingapp rest-api

Response signer and request forwarder for sawtooth-rest-api with custom endpoints.

> Published with kind permission from [vidaloop](https://www.vidaloop.com/vidaloop-innovator-in-mobile-voting-shutdown-of-operations).

## setup

The rest-api is intended to sit in front of sawtooth rest-api and relay requests to the same. This allows us to incrementally replace functionality of upstream rest-api where needed.

To use it, just start the server.

    cargo run

And simply change the destination port of your client requests. Default port is `3030`. The following will get election settings from a ledger populated by local e2e tests.

    curl localhost:3030/state/e24b31a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3

To run e2e tests against this rest-api, simply set the `SAWTOOTH_REST_API` variable in your environment.

    SAWTOOTH_API_URI="http://localhost:3030"

## development
Make sure you have `rustup` and your are on the stable toolchain.

  * https://rustup.rs/
  * `rustup show`

for development you can get the server to restart on code changes like so:

    cargo watch -x run

## helpful utilities

  * curl --header "Content-Type: application/json"   --request POST   --data '{"data": [1,2,3,4]}' \  http://localhost:3030/batches
  * sudo tcpdump -i any -n -S -s 0 -A 'tcp dst port 8080'

### viewing headers

    curl -s -i localhost:3030/state/e24b31896d78f1febad66e62b993626df726cb1949afebec8d959ea7de85fea2ea5775|head -n 6

you should get back something like:

    HTTP/1.1 200 OK
    date: 2022-03-23 18:28:49.131131153 UTC
    digest: SHA-256="3fb997211314d8434754b842d4ac2f47dc5a2e5ae8874567376a657296b50fae"
    va-signature-chain: MIICAAIUPks75RLknLDdjoK99NAXRTfZSsAwCgYIKoZIzj0EAwIwgZwxJTAjBgNVBAMMHFZvdGluZ0FwcCBJbnRlcm1lZGlhdGUgLSBERVYxEzARBgNVBAgMCkNhbGlmb3JuaWExCzAJBgNVBAYTAlVTMR8wHQYJKoZIhvcNAQkBFhBjYUB2b3RpbmdhcHAuY29tMRYwFAYDVQQKDA1WaWRhbG9vcCwgSW5jMRgwFgYDVQQLDA9Wb3RpbmdBcHAgLSBERVYwHhcNMjIwMzE0MjAwNzQwWhcNMjYwMzEzMjAwNzQwWjCBpDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExEDAOBgNVBAcMB0xhIE1lc2ExETAPBgNVBAoMCFZpZGFsb29wMR4wHAYDVQQLDBVWb3RpbmdBcHAgRGV2ZWxvcG1lbnQxOzA5BgNVBAMMMlNlY3VyaXR5IERldmljZSBTWG9hUW9HNzJKIHNlY2Rldi1sZWRnZXItc2lnbmF0dXJlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE1qEJhaI9VMWk62bWNjTwLMUyOIq93R6JWcrqaEs06YikH1rbNNSCGQcIcqZf0ERoA9s+NCtEQ+G8asXDa1dvu7SetnO0/TBnV7Iu0nSC2ADPWAS5grg1/Hzi5EUYlf2J
    signature: keyId="71b6b30005df16ff6a5f6eaa3f09e7285b7c1765f5e47849e3cacfdf3ed601c2",algorithm="ecdsa-sha256",headers="date:2022-03-23 18:28:49.131131153 UTC,digest:SHA-256="3fb997211314d8434754b842d4ac2f47dc5a2e5ae8874567376a657296b50fae",(request-target):get state/e24b31896d78f1febad66e62b993626df726cb1949afebec8d959ea7de85fea2ea5775",signature="8d3d7ef3b78eba3106f656bf4d6b433d71c50622e588d83e83a702c4c060bbb3cd785dd0e44f693b6333837a3be57e3a6e06240652210e47eaa88e27b1d44105"
    content-length: 39623
