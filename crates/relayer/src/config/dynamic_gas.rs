use serde::de::Error as DeserializeError;
use serde::de::Unexpected;
use serde::Deserialize;
use serde::Deserializer;
use serde_derive::Serialize;

flex_error::define_error! {
    Error {
        MultiplierTooSmall
            { value: f64 }
            |e| {
                format_args!("`multiplier` in dynamic_gas configuration must be greater than or equal to {}, found {}",
                DynamicGasPrice::MIN_MULTIPLIER, e.value)
            },
    }
}

/// Where the dynamic gas price is read from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DynamicGasBackend {
    /// Chosen from the chain id, as Hermes does: Osmosis' EIP-1559 module for
    /// Osmosis chains, Skip's feemarket module otherwise.
    #[default]
    Auto,
    /// Osmosis `txfees` EIP-1559 base fee.
    Osmosis,
    /// Skip `feemarket` gas prices.
    SkipFeemarket,
    /// The `cosmos/evm` fee market base fee (`cosmos.evm.feemarket.v1`),
    /// which also prices Cosmos transactions on chains such as QoreChain.
    CosmosEvmFeemarket,
}

impl DynamicGasBackend {
    fn is_auto(&self) -> bool {
        *self == DynamicGasBackend::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize)]
pub struct DynamicGasPrice {
    pub enabled: bool,
    pub multiplier: f64,
    pub max: f64,
    #[serde(skip_serializing_if = "DynamicGasBackend::is_auto")]
    pub backend: DynamicGasBackend,
}

impl DynamicGasPrice {
    const DEFAULT_MULTIPLIER: f64 = 1.1;
    const DEFAULT_MAX: f64 = 0.6;
    const MIN_MULTIPLIER: f64 = 1.0;

    pub fn enabled(multiplier: f64, max: f64) -> Result<Self, Error> {
        Self::new(true, multiplier, max)
    }

    pub fn disabled() -> Self {
        Self {
            enabled: false,
            multiplier: Self::DEFAULT_MULTIPLIER,
            max: Self::DEFAULT_MAX,
            backend: DynamicGasBackend::Auto,
        }
    }

    pub fn new(enabled: bool, multiplier: f64, max: f64) -> Result<Self, Error> {
        if multiplier < Self::MIN_MULTIPLIER {
            return Err(Error::multiplier_too_small(multiplier));
        }

        Ok(Self {
            enabled,
            multiplier,
            max,
            backend: DynamicGasBackend::Auto,
        })
    }

    // Unsafe GasMultiplier used for test cases only.
    pub fn unsafe_new(enabled: bool, multiplier: f64, max: f64) -> Self {
        Self {
            enabled,
            multiplier,
            max,
            backend: DynamicGasBackend::Auto,
        }
    }

    pub fn with_backend(mut self, backend: DynamicGasBackend) -> Self {
        self.backend = backend;
        self
    }
}

impl Default for DynamicGasPrice {
    fn default() -> Self {
        Self::disabled()
    }
}

impl<'de> Deserialize<'de> for DynamicGasPrice {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DynGas {
            enabled: bool,
            multiplier: f64,
            max: f64,
            #[serde(default)]
            backend: DynamicGasBackend,
        }

        let DynGas {
            enabled,
            multiplier,
            max,
            backend,
        } = DynGas::deserialize(deserializer)?;

        DynamicGasPrice::new(enabled, multiplier, max)
            .map(|d| d.with_backend(backend))
            .map_err(|e| match e.detail() {
                ErrorDetail::MultiplierTooSmall(_) => D::Error::invalid_value(
                    Unexpected::Float(multiplier),
                    &format!(
                        "a floating-point value greater than {}",
                        Self::MIN_MULTIPLIER
                    )
                    .as_str(),
                ),
            })
    }
}

#[cfg(test)]
#[allow(dead_code)] // the field of the struct `DummyConfig` defined below is never accessed
mod tests {
    use super::*;

    use serde::Deserialize;
    use test_log::test;

    #[test]
    fn parse_invalid_gas_multiplier() {
        #[derive(Debug, Deserialize)]
        struct DummyConfig {
            dynamic_gas: DynamicGasPrice,
        }

        let err = toml::from_str::<DummyConfig>(
            "dynamic_gas = { enabled = true, multiplier = 0.9, max = 0.6 }",
        )
        .unwrap_err()
        .to_string();

        println!("err: {err}");

        assert!(err.contains("expected a floating-point value greater than"));
    }

    #[test]
    fn parse_backend() {
        #[derive(Debug, Deserialize)]
        struct DummyConfig {
            dynamic_gas: DynamicGasPrice,
        }

        let c = toml::from_str::<DummyConfig>(
            "dynamic_gas = { enabled = true, multiplier = 1.0, max = 1.0, backend = \"cosmos-evm-feemarket\" }",
        )
        .unwrap();
        assert_eq!(c.dynamic_gas.backend, DynamicGasBackend::CosmosEvmFeemarket);

        let c = toml::from_str::<DummyConfig>(
            "dynamic_gas = { enabled = true, multiplier = 1.1, max = 0.6 }",
        )
        .unwrap();
        assert_eq!(c.dynamic_gas.backend, DynamicGasBackend::Auto);
    }

    #[test]
    fn safe_gas_multiplier() {
        let dynamic_gas = DynamicGasPrice::new(true, 0.6, 0.6);
        assert!(
            dynamic_gas.is_err(),
            "Gas multiplier should be an error if value is lower than 1.0: {dynamic_gas:?}"
        );
    }

    #[test]
    fn unsafe_gas_multiplier() {
        let dynamic_gas = DynamicGasPrice::unsafe_new(true, 0.6, 0.4);
        assert_eq!(dynamic_gas.multiplier, 0.6);
        assert_eq!(dynamic_gas.max, 0.4);
    }
}
