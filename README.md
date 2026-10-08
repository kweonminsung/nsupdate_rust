# BIND9 nsupdate for Rust

An asynchronous Rust client for DNS UPDATE (RFC 2136), with optional TSIG
authentication, UDP/TCP transport, and IPv4/IPv6 support.

Requires Rust 1.88 or later and a Tokio runtime.

## Installation

```toml
[dependencies]
nsupdate = "0.1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Example usage

The example adds an A record using the Docker test server described below.
For your own server, replace the address, zone, key name, and base64-encoded
shared secret with values from your BIND configuration.

```no_run
use nsupdate::{NsUpdateClient, RData, TsigKey, UpdateMessageBuilder};
use std::{error::Error, net::Ipv4Addr, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Public test key; replace with your server's shared key.
    let key = TsigKey::new("sha256", "test-sha256.", "dGVzdA==")?;
    let client = NsUpdateClient::new("127.0.0.1:15354", Some(key))
        .with_timeout(Duration::from_secs(5))?;

    let message = UpdateMessageBuilder::new("example.test")
        .add_record("host.example.test", 300, RData::A(Ipv4Addr::new(192, 0, 2, 123)))
        .build()?;
    let response = client.send(&message).await?;
    if !response.is_success() {
        return Err(format!("DNS UPDATE failed: RCODE {}", response.rcode()).into());
    }
    println!("Update succeeded; authenticated={}", response.is_authenticated());
    Ok(())
}
```

Example output:

```text
Update succeeded; authenticated=true
```

Request encoding and I/O failures return `Err(NsUpdateError)`.
Response validation failures are returned immediately for TCP;
UDP discards invalid responses as described below.
A DNS error such as `REFUSED` returns `Ok(UpdateResponse)` with `is_success() == false`;
check `rcode()` for the server's response code.

## Operations

Builder update methods run in call order. Delete an RRset and then add records
in the same message to replace its values and TTL atomically. Prerequisites are
checked against the zone before any updates in the message are applied.

| Method | Operation |
|---|---|
| `add_record(name, ttl, rdata)` | Add a record, inferring its type from `RData` |
| `delete_record(name, rtype)` | Delete an RRset; type `255` deletes all RRsets at the name |
| `delete_record_value(name, rdata)` | Delete only the matching value |
| `require_name_exists(name)` / `require_name_absent(name)` | Require records to exist / not exist at the name |
| `require_rrset_exists(name, rtype)` / `require_rrset_absent(name, rtype)` | Require an RRset to exist / not exist |
| `require_rrset_equals(name, values)` | Require the entire RRset to match the supplied values, ignoring order and TTL |

Record type numbers include A (`1`), TXT (`16`), and AAAA (`28`). RRset presence
methods require a concrete type; use the name methods for an ANY-type condition.
`require_rrset_equals` takes a nonempty iterator of `RData` values of one type.
Repeated calls for the same name and type combine their values.

Supported RDATA types are A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, and TXT.
TXT currently contains one UTF-8 string of at most 255 bytes; multiple strings
in one TXT record and arbitrary raw RDATA are not supported.

Updates use class IN and one explicitly specified zone. Names are absolute,
with an optional trailing dot. Use ASCII names, DNS `\X` / `\DDD` escapes,
or Punycode for internationalized names. TTLs must be in `0..=2147483647`.
SOA additions and replacements require a nonzero serial. Prerequisites can
compare an existing SOA whose serial is zero.

## Authentication and transport

`Some(TsigKey)` signs requests and requires verified TSIG responses. Supported
algorithms are `md5`, `sha1`, `sha224`, `sha256`, `sha384`, and `sha512`;
the `hmac-` prefix is also accepted. Empty secrets return
`NsUpdateError::EmptyTsigKey`. Key debug output redacts the secret.

Pass `None` for unsigned updates. The server must allow them for the zone.
This example uses TCP to delete an A RRset from the unsigned test zone:

```no_run
use nsupdate::{NsUpdateClient, Transport, UpdateMessageBuilder};
use std::{error::Error, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let client = NsUpdateClient::new("127.0.0.1:15354", None)
        .with_transport(Transport::Tcp)
        .with_timeout(Duration::from_secs(5))?;
    let message = UpdateMessageBuilder::new("unsigned.test")
        .delete_record("host.unsigned.test", 1)
        .build()?;
    let response = client.send(&message).await?;
    if !response.is_success() {
        return Err(format!("DNS UPDATE failed: RCODE {}", response.rcode()).into());
    }
    println!("Update succeeded; authenticated={}", response.is_authenticated());
    Ok(())
}
```

| Transport | Behavior |
|---|---|
| `Auto` (default) | Use UDP for requests up to 512 bytes including TSIG, otherwise TCP; retry a validated truncated UDP response over TCP |
| `Udp` | Reject requests over 512 bytes and report truncated responses |
| `Tcp` | Open a new TCP connection for each request |

Server addresses use `host:port` or `[IPv6]:port`, such as `[::1]:53`.
I/O failures are returned without automatically resending the update.

UDP requests discard malformed responses and responses that fail request matching
or TSIG checks, then continue receiving on the same socket without resending the
request. This also applies to unexpected TSIG responses to unsigned requests.
Valid DNS errors and authenticated TSIG errors are returned immediately.
Only a validated truncated response triggers the automatic TCP fallback.

## Timeouts and limits

The default timeout is `None`. `with_timeout(Duration)` and
`with_timeout(Some(Duration))` set a shared deadline for address resolution and
network I/O, including UDP-to-TCP fallback. `with_timeout(None)` disables it.
Zero or excessively large durations return `NsUpdateError::InvalidTimeout`;
expiration returns `NsUpdateError::Timeout`.
Discarded UDP responses do not reset the deadline. With no timeout, a UDP
request can wait indefinitely if the server only sends invalid responses,
including unsigned TSIG errors caused by a wrong key.

DNS messages, including TSIG, cannot exceed 65,535 bytes.

## Tests

Run the unit tests, mock-server integration tests, and README compile checks:

```sh
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

The BIND integration tests are ignored by default. Start an isolated server
from the repository root:

```sh
docker run -d --rm --name nsupdate-test \
  -p 127.0.0.1:15354:53/udp -p 127.0.0.1:15354:53/tcp \
  --mount type=bind,src="$PWD/tests/bind",dst=/fixtures,readonly \
  --entrypoint named ubuntu/bind9:9.20-26.04 -g -c /fixtures/named.conf
```

Wait until the zone is available, then run the tests:

```sh
dig @127.0.0.1 -p 15354 example.test SOA +short
NSUPDATE_TEST_SERVER=127.0.0.1:15354 cargo test --locked --test bind -- --ignored
```

This server uses public test keys. `example.test` requires TSIG,
`unsigned.test` accepts unsigned updates, and `refused.test` rejects updates.
The tests cover UDP/TCP, all supported HMAC algorithms, prerequisites, and
record additions and deletions. Remove the server after testing:

```sh
docker stop nsupdate-test
```

## Publishing

To check the package before publishing:

```sh
cargo package --locked --list
cargo publish --locked --dry-run
```

## License

Mozilla Public License 2.0. See [LICENSE](https://github.com/kweonminsung/nsupdate_rust/blob/main/LICENSE).
