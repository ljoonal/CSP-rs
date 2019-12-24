//! This crate is a helper to quickly construct a CSP and then turn it into a String.
//!
//! This library can help you when you don't want to remember some weird formatting rules of CSP, and want to avoid typos.
//! And it certainly can be handy if you need to re-use things, for example a list of sources (just .clone() them everywhere and you're good to go!).
//!
//! WARNING: this library does not care if you create invalid CSP rules, and mostly allows it.
//! But it does force you to use a typed structure, so it'll be harder to mess up than when manually writing CSP.
//! Another thing that this crate does not do: It does not do any base64 or percent encoding or anything like that.
//!
//! # Example usage
//! ```rust
//! use csp::{CSP, Directive, Sources, Source};
//!
//! let csp = CSP::new()
//!   .add(Directive::ImgSrc(
//!     Sources::new_with(Source::Self_)
//!       .add(Source::Host("https://*.example.org"))
//!       .add(Source::Host("https://shields.io")),
//!   ))
//!   .add(Directive::ConnectSrc(
//!     Sources::new()
//!       .add(Source::Host("http://crates.io"))
//!       .add(Source::Scheme("https"))
//!       .add(Source::Self_),
//!   ))
//!   .add(Directive::StyleSrc(
//!     Sources::new_with(Source::Self_).add(Source::UnsafeInline),
//!   ))
//!   .add(Directive::ObjectSrc(Sources::new()));
//!
//! let csp_header = "Content-Security-Policy: ".to_owned() + &csp.to_string();
//! ```
//! # Copyright notice for this crate's docs:
//! Most of the comments for various CSP things are from [MDN](https://developer.mozilla.org/en-US/docs/MDN/About), so they licensed under [CC-BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/)
//! So attribution of most of the docs goes to [Mozilla Contributors](https://developer.mozilla.org/en-US/docs/MDN/About$history).
//!
//! Please go to MDN to read up to date docs, as these ones might not be up to date.
use std::fmt;

#[cfg(test)]
mod test;

mod directive;
mod plugin;
mod report_uri;
mod sandbox;
mod source;
mod sri;
mod trusted_type;

pub use directive::*;
pub use plugin::*;
pub use report_uri::*;
pub use sandbox::*;
pub use source::*;
pub use sri::*;
pub use trusted_type::*;

#[derive(Debug, Clone)]
/// The starting point for building a Content Security Policy.
///
/// You'll add [`Directive`] into this struct, and later on call .to_string() on it to get it as a header compatible string.
/// Doesn't include content-security-policy: part in it though.
///
/// [`Directive`]: Directive
pub struct CSP<'a>(Vec<Directive<'a>>);

impl<'a> CSP<'a> {
  pub fn new() -> Self {
    CSP(vec![])
  }

  pub fn new_with(directive: Directive<'a>) -> Self {
    CSP(vec![directive])
  }

  #[cfg(not(feature = "allow_duplicate_directives"))]
  pub fn add_borrowed<'b>(&'b mut self, directive: Directive<'a>) -> &'b mut Self {
    for existing_directive in self.0.iter_mut() {
      if std::mem::discriminant(&directive) == std::mem::discriminant(&existing_directive) {
        *existing_directive = directive;
        return self;
      }
    }

    self.0.push(directive);
    self
  }

  #[cfg(feature = "allow_duplicate_directives")]
  pub fn add_borrowed<'b>(&'b mut self, directive: Directive<'a>) -> &'b mut Self {
    self.0.push(directive);
    self
  }

  pub fn add(mut self, directive: Directive<'a>) -> Self {
    self.add_borrowed(directive);
    self
  }
}

impl<'a> fmt::Display for CSP<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.len() < 1 {
      return write!(fmt, "");
    }

    let mut formatted_string = String::new();

    for directive in &self.0[0..self.0.len() - 1] {
      formatted_string.push_str(&directive.to_string());
      formatted_string.push_str("; ");
    }

    formatted_string.push_str(&self.0[self.0.len() - 1].to_string());
    write!(fmt, "{}", formatted_string)
  }
}
