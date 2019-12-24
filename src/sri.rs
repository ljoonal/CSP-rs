use std::fmt;

#[derive(Debug, Clone)]
/// Used for `RequireSriFor` [`Directive`].
///
/// [`Directive`]: Directive
pub enum SriFor {
  /// Requires SRI for scripts.
  Script,
  /// Requires SRI for style sheets.
  Style,
  /// Requires SRI for both, scripts and style sheets.
  ScriptStyle,
}

impl fmt::Display for SriFor {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    write!(
      fmt,
      "{}",
      match self {
        Self::Script => "script",
        Self::Style => "style",
        Self::ScriptStyle => "script style",
      }
    )
  }
}
