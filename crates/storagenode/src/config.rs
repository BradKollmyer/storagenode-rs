//! Process configuration from the environment.
//!
//! Required: `STORJ_S3_ENDPOINT`, `STORJ_S3_BUCKET`, `STORJ_S3_ACCESS_KEY_ID`,
//! `STORJ_S3_SECRET_ACCESS_KEY`, `STORJ_OPERATOR_EMAIL`, `STORJ_OPERATOR_WALLET`,
//! `STORJ_CONTACT_EXTERNAL_ADDRESS`, `STORJ_SATELLITES`.
//!
//! Optional: `STORJ_S3_REGION` (`us-east-1`), `STORJ_S3_PREFIX` (`pieces`),
//! `STORJ_S3_PATH_STYLE` (`true` or `false`), `STORJ_ALLOCATED_BYTES`,
//! `STORJ_VOLUME` (`/var/lib/storj`), `STORJ_OPERATOR_WALLET_FEATURES`
//! (comma-separated).

use std::net::{Ipv4Addr, SocketAddr};

use storj_rpc::{NodeUrl, parse_node_url};

/// TCP and UDP port for DRPC. UDP is QUIC.
pub const LISTEN_PORT: u16 = 28967;

/// HTTP port for the Vue dashboard. `0.0.0.0`, not the Go loopback default.
pub const DASHBOARD_PORT: u16 = 14002;

/// Settings the binary reads once at startup.
#[derive(Clone, Debug)]
pub struct Config {
    /// Bucket client and the volume directory (`pieces.db`, identity).
    pub s3: s3store::Config,
    /// `STORJ_OPERATOR_EMAIL`. Required and non-empty.
    pub operator_email: String,
    /// `STORJ_OPERATOR_WALLET`. `0x` plus 40 hex characters.
    pub operator_wallet: String,
    /// `STORJ_OPERATOR_WALLET_FEATURES`. Empty when the variable is unset.
    pub wallet_features: Vec<String>,
    /// `STORJ_CONTACT_EXTERNAL_ADDRESS`. Sent as the check-in address.
    pub contact_external_address: String,
    /// Trusted satellites from `STORJ_SATELLITES` (comma-separated node URLs).
    pub satellites: Vec<NodeUrl>,
    /// DRPC listen address. Always `0.0.0.0:28967`.
    pub listen: SocketAddr,
}

/// Rejected environment.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A required variable was missing or empty.
    #[error("{0} is required")]
    Required(&'static str),
    /// The wallet was not `0x` plus 40 hex characters.
    #[error("STORJ_OPERATOR_WALLET must match ^0x[a-fA-F0-9]{{40}}$")]
    Wallet,
    /// A satellite URL could not be parsed.
    #[error("STORJ_SATELLITES entry {url:?}: {message}")]
    Satellite {
        /// The entry that failed.
        url: String,
        /// Parser message.
        message: String,
    },
    /// `STORJ_ALLOCATED_BYTES` was not an integer.
    #[error("STORJ_ALLOCATED_BYTES: {0}")]
    Allocated(String),
    /// `STORJ_CONTACT_EXTERNAL_ADDRESS` was not `host:port`.
    #[error("STORJ_CONTACT_EXTERNAL_ADDRESS must be host:port")]
    ExternalAddress,
    /// `STORJ_S3_PATH_STYLE` was not `true` or `false`.
    #[error("STORJ_S3_PATH_STYLE must be true or false")]
    PathStyle,
}

impl Config {
    /// Reads process environment variables.
    pub fn from_env() -> Result<Self, Error> {
        Self::from_fn(|key| std::env::var(key).ok())
    }

    /// Reads settings through `get`. Missing and empty values are the same.
    pub fn from_fn(get: impl Fn(&str) -> Option<String>) -> Result<Self, Error> {
        let endpoint = required(&get, "STORJ_S3_ENDPOINT")?;
        let bucket = required(&get, "STORJ_S3_BUCKET")?;
        let access_key_id = required(&get, "STORJ_S3_ACCESS_KEY_ID")?;
        let secret_access_key = required(&get, "STORJ_S3_SECRET_ACCESS_KEY")?;
        let operator_email = required(&get, "STORJ_OPERATOR_EMAIL")?;
        let operator_wallet = required(&get, "STORJ_OPERATOR_WALLET")?;
        if !valid_wallet(&operator_wallet) {
            return Err(Error::Wallet);
        }
        let contact_external_address = required(&get, "STORJ_CONTACT_EXTERNAL_ADDRESS")?;
        if !valid_address(&contact_external_address) {
            return Err(Error::ExternalAddress);
        }
        let wallet_features = optional(&get, "STORJ_OPERATOR_WALLET_FEATURES")
            .map(|value| {
                value
                    .split(',')
                    .map(|part| part.trim().to_owned())
                    .filter(|part| !part.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        let satellites = parse_satellites(&required(&get, "STORJ_SATELLITES")?)?;

        let region = optional(&get, "STORJ_S3_REGION").unwrap_or_else(|| "us-east-1".to_owned());
        let prefix = optional(&get, "STORJ_S3_PREFIX").unwrap_or_else(|| "pieces".to_owned());
        let path_style = match optional(&get, "STORJ_S3_PATH_STYLE").as_deref() {
            None => None,
            Some("true") => Some(true),
            Some("false") => Some(false),
            Some(_) => return Err(Error::PathStyle),
        };
        let allocated_bytes = match optional(&get, "STORJ_ALLOCATED_BYTES") {
            None => 0,
            Some(value) => value
                .parse::<u64>()
                .map_err(|err| Error::Allocated(err.to_string()))?,
        };

        Ok(Self {
            s3: s3store::Config {
                endpoint,
                bucket,
                access_key_id,
                secret_access_key,
                region,
                prefix,
                path_style,
                volume: optional(&get, "STORJ_VOLUME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_else(|| std::path::PathBuf::from("/var/lib/storj")),
                allocated_bytes,
            },
            operator_email,
            operator_wallet,
            wallet_features,
            contact_external_address,
            satellites,
            listen: SocketAddr::from((Ipv4Addr::UNSPECIFIED, LISTEN_PORT)),
        })
    }
}

fn required(get: &impl Fn(&str) -> Option<String>, key: &'static str) -> Result<String, Error> {
    match optional(get, key) {
        Some(value) => Ok(value),
        None => Err(Error::Required(key)),
    }
}

fn optional(get: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    get(key)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn parse_satellites(raw: &str) -> Result<Vec<NodeUrl>, Error> {
    let mut satellites = Vec::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let url = parse_node_url(entry).map_err(|err| Error::Satellite {
            url: entry.to_owned(),
            message: err.to_string(),
        })?;
        satellites.push(url);
    }
    if satellites.is_empty() {
        return Err(Error::Required("STORJ_SATELLITES"));
    }
    Ok(satellites)
}

/// `^0x[a-fA-F0-9]{40}$`.
fn valid_wallet(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("0x") else {
        return false;
    };
    rest.len() == 40 && rest.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A `host:port` satellites can dial back. The host is a name, an IPv4
/// address, or a bracketed IPv6 literal. It is checked for shape, not
/// resolution: an unbracketed colon is read as another port separator, and
/// the node would advertise an address satellites cannot dial.
fn valid_address(value: &str) -> bool {
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if !port.parse::<u16>().is_ok_and(|port| port > 0) {
        return false;
    }
    let host = if let Some(inner) = host.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return false;
        };
        if inner.is_empty() || inner.contains('[') || inner.contains(']') {
            return false;
        }
        inner
    } else if host.contains(':') || host.contains('[') || host.contains(']') {
        return false;
    } else {
        host
    };
    !host.is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(extra: &[(&str, &str)]) -> Result<Config, Error> {
        let mut pairs = vec![
            ("STORJ_S3_ENDPOINT", "http://127.0.0.1:9000"),
            ("STORJ_S3_BUCKET", "pieces"),
            ("STORJ_S3_ACCESS_KEY_ID", "ak"),
            ("STORJ_S3_SECRET_ACCESS_KEY", "sk"),
            ("STORJ_OPERATOR_EMAIL", "op@example.com"),
            (
                "STORJ_OPERATOR_WALLET",
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("STORJ_CONTACT_EXTERNAL_ADDRESS", "203.0.113.5:28967"),
            ("STORJ_SATELLITES", "us-central-1.tardigrade.io:7777"),
        ];
        pairs.extend_from_slice(extra);
        Config::from_fn(|key| {
            // Later pairs override the defaults, matching a second env assignment.
            pairs
                .iter()
                .rev()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn parses_operator_wallet_and_known_satellite() {
        let config = sample(&[
            ("STORJ_ALLOCATED_BYTES", "1000"),
            ("STORJ_S3_PATH_STYLE", "true"),
            ("STORJ_S3_PREFIX", "custom"),
        ])
        .expect("config");
        assert_eq!(config.operator_email, "op@example.com");
        assert!(config.wallet_features.is_empty());
        assert_eq!(config.s3.allocated_bytes, 1000);
        assert_eq!(config.s3.path_style, Some(true));
        assert_eq!(config.s3.prefix, "custom");
        assert_eq!(config.listen.port(), LISTEN_PORT);
        assert!(config.listen.ip().is_unspecified());
        assert_eq!(DASHBOARD_PORT, 14002);
        assert_eq!(config.satellites.len(), 1);
        assert!(!config.satellites[0].id.is_zero());
        assert_eq!(
            config.satellites[0].address,
            "us-central-1.tardigrade.io:7777"
        );
    }

    #[test]
    fn rejects_empty_wallet_email_and_bad_address() {
        let err = sample(&[("STORJ_OPERATOR_WALLET", "")]).unwrap_err();
        assert!(matches!(err, Error::Required("STORJ_OPERATOR_WALLET")));
        let err = sample(&[("STORJ_OPERATOR_WALLET", "0x1234")]).unwrap_err();
        assert!(matches!(err, Error::Wallet));
        let err = sample(&[("STORJ_OPERATOR_EMAIL", "  ")]).unwrap_err();
        assert!(matches!(err, Error::Required("STORJ_OPERATOR_EMAIL")));
        let err = sample(&[("STORJ_S3_PATH_STYLE", "yes")]).unwrap_err();
        assert!(matches!(err, Error::PathStyle));
        let err = sample(&[("STORJ_SATELLITES", "us1.storj.io:7777")]).unwrap_err();
        assert!(matches!(err, Error::Satellite { .. }), "{err}");
        for bad in [
            "example.com",
            "example.com:",
            "example.com:0",
            ":28967",
            "example.com:99999",
            "2001:db8::1",
            "2001:db8::1:28967",
            "example.com:28967:1",
            "[]:28967",
            "[2001:db8::1",
            "2001:db8::1]:28967",
            "[[2001:db8::1]]:28967",
        ] {
            let err = sample(&[("STORJ_CONTACT_EXTERNAL_ADDRESS", bad)]).unwrap_err();
            assert!(matches!(err, Error::ExternalAddress), "{bad}: {err}");
        }
        for good in [
            "example.com:28967",
            "203.0.113.5:28967",
            "[2001:db8::9]:28967",
            "[::1]:28967",
        ] {
            sample(&[("STORJ_CONTACT_EXTERNAL_ADDRESS", good)]).expect(good);
        }
    }

    #[test]
    fn splits_wallet_features_and_keeps_known_satellite_ids() {
        let config =
            sample(&[("STORJ_OPERATOR_WALLET_FEATURES", "alpha, beta,, gamma ")]).expect("config");
        assert_eq!(config.wallet_features, ["alpha", "beta", "gamma"]);
        let config = sample(&[("STORJ_SATELLITES", "saltlake.tardigrade.io:7777")]).expect("known");
        assert!(!config.satellites[0].id.is_zero());
        assert_eq!(config.satellites[0].address, "saltlake.tardigrade.io:7777");
    }
}
