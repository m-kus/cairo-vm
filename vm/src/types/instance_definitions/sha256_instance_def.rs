use serde::Serialize;

pub(crate) const CELLS_PER_SHA256: u32 = 24;
pub(crate) const INPUT_CELLS_PER_SHA256: u32 = 16;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub(crate) struct Sha256InstanceDef {
    pub(crate) ratio: Option<u32>,
}

impl Default for Sha256InstanceDef {
    fn default() -> Self {
        Sha256InstanceDef { ratio: Some(64) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let builtin_instance = Sha256InstanceDef { ratio: Some(64) };
        assert_eq!(Sha256InstanceDef::default(), builtin_instance);
    }
}
