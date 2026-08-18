use serde::de::{self, Deserializer, Visitor};
use serde::Deserialize;
use std::fmt;

/// Helper function to deserialize fields that can be either string or number
pub fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    // Define a visitor to handle different types
    struct StringOrNumberVisitor;

    impl<'de> Visitor<'de> for StringOrNumberVisitor {
        type Value = Option<String>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or number")
        }

        // Handle string
        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle i64
        fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle u64
        fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle f64
        fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Some(value.to_string()))
        }

        // Handle None
        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        // Handle null
        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrNumberVisitor)
}

/// Deserialize a field that may be either a single string or a sequence of
/// strings into `Option<Vec<String>>`. Clash configs in the wild use both
/// forms for fields like `alpn` (`alpn: h3` and `alpn: [h3, h2]`).
pub fn deserialize_string_or_vec<'de, D>(deserializer: D) -> Result<Option<Vec<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct StringOrVecVisitor;

    impl<'de> Visitor<'de> for StringOrVecVisitor {
        type Value = Option<Vec<String>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string or sequence of strings")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.is_empty() {
                return Ok(None);
            }
            Ok(Some(
                value.split(',').map(|s| s.trim().to_string()).collect(),
            ))
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut values = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                values.push(value);
            }
            Ok(Some(values))
        }

        fn visit_none<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }

        fn visit_unit<E>(self) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(None)
        }
    }

    deserializer.deserialize_any(StringOrVecVisitor)
}

/// Deserialize a value treating an explicit `null` (empty YAML key) as the
/// type's default. Useful for optional list sections like `tasks:` left empty
/// in a config file.
pub fn deserialize_null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    let opt = Option::<T>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

/// Parse a bandwidth value like `1000`, `"1000"`, `"1000 Mbps"`, `"1.5 Gbps"`
/// or `"500 Kbps"` into whole Mbps. Returns 0 when the value cannot be parsed.
pub fn parse_speed_mbps(value: &str) -> u32 {
    let value = value.trim();
    if value.is_empty() {
        return 0;
    }

    // Split into leading number and trailing unit
    let number_end = value
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(value.len());
    let (number_part, unit_part) = value.split_at(number_end);
    let number: f64 = match number_part.trim().parse() {
        Ok(n) => n,
        Err(_) => return 0,
    };

    let multiplier = match unit_part.trim().to_lowercase().as_str() {
        "" | "m" | "mbps" | "mbit" => 1.0,
        "k" | "kbps" | "kbit" => 0.001,
        "g" | "gbps" | "gbit" => 1000.0,
        "t" | "tbps" | "tbit" => 1_000_000.0,
        _ => 1.0,
    };

    (number * multiplier).round() as u32
}

#[cfg(test)]
mod tests {
    use super::parse_speed_mbps;

    #[test]
    fn test_parse_speed_mbps() {
        assert_eq!(parse_speed_mbps("1000"), 1000);
        assert_eq!(parse_speed_mbps("1000 Mbps"), 1000);
        assert_eq!(parse_speed_mbps("1000Mbps"), 1000);
        assert_eq!(parse_speed_mbps("1.5 Gbps"), 1500);
        assert_eq!(parse_speed_mbps("500 Kbps"), 1);
        assert_eq!(parse_speed_mbps(""), 0);
        assert_eq!(parse_speed_mbps("abc"), 0);
    }
}
