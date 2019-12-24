use std::fmt;

#[derive(Debug, Clone)]
/// A struct to give source(s) to a [`Directive`] which might require it.
///
/// # Example usage
/// ```rust
/// use csp::{Sources, Source};
///
/// let sources = Sources::new().add(Source::Self_).add(Source::Scheme("data"));
///
/// assert_eq!(sources.to_string(), "'self' data:");
///```
///
/// [`Directive`]: Directive
pub struct Sources<'a>(Vec<Source<'a>>);

#[derive(Debug, Clone)]
/// The source that a bunch of directives can have multiple of.
///
/// If nothing gets added, becomes 'none'.
pub enum Source<'a> {
  /// Internet hosts by name or IP address, as well as an optional URL scheme and/or port number.
  ///
  /// The site's address may include an optional leading wildcard (the asterisk character, '*'), and you may use a wildcard (again, '*') as the port number, indicating that all legal ports are valid for the source.
  /// Examples:
  /// - `http://*.example.com`: Matches all attempts to load from any subdomain of example.com using the `http:` URL scheme.
  /// - `mail.example.com:443`: Matches all attempts to access port 443 on mail.example.com.
  /// - `https://store.example.com`: Matches all attempts to access store.example.com using https:.
  Host(&'a str),
  /// A schema such as 'http' or 'https'.
  ///
  ///  The colon is automatically added to the end. You can also specify data schemas (not recommended).
  /// - `data` Allows data: URIs to be used as a content source. This is insecure; an attacker can also inject arbitrary data: URIs. Use this sparingly and definitely not for scripts.
  /// - `mediastream` Allows `mediastream:` URIs to be used as a content source.
  /// - `blob` Allows `blob:` URIs to be used as a content source.
  /// - `filesystem` Allows `filesystem:` URIs to be used as a content source.
  Scheme(&'a str),
  /// Refers to the origin from which the protected document is being served, including the same URL scheme and port number.
  ///
  /// Some browsers specifically exclude `blob` and `filesystem` from source directives. Sites needing to allow these content types can specify them using the Data attribute.
  Self_,
  /// Allows the use of `eval()` and similar methods for creating code from strings.
  UnsafeEval,
  /// Allows to enable specific inline event handlers. If you only need to allow inline event handlers and not inline <script> elements or `javascript:` URLs, this is a safer method compared to using the `unsafe-inline` expression.
  UnsafeHashes,
  /// Allows the use of inline resources, such as inline \<script> elements, javascript: URLs, inline event handlers, and inline <style> elements.
  UnsafeInline,
  /// A whitelist for specific inline scripts using a cryptographic nonce (number used once). The server must generate a unique nonce value each time it transmits a policy. It is critical to provide an unguessable nonce, as bypassing a resource’s policy is otherwise trivial. See unsafe inline script for an example. Specifying nonce makes a modern browser ignore `'unsafe-inline'` which could still be set for older browsers without nonce support.
  Nonce(&'a str),
  /// A sha256, sha384 or sha512 hash of scripts or styles. The use of this source consists of two portions separated by a dash: the encryption algorithm used to create the hash and the base64-encoded hash of the script or style. When generating the hash, don't include the \<script> or \<style> tags and note that capitalization and whitespace matter, including leading or trailing whitespace. See unsafe inline script for an example. In CSP 2.0 this applied only to inline scripts. CSP 3.0 allows it in the case of `script-src` for external scripts.
  Hash((&'a str, &'a str)),
  /// The `strict-dynamic` source expression specifies that the trust explicitly given to a script present in the markup, by accompanying it with a nonce or a hash, shall be propagated to all the scripts loaded by that root script. At the same time, any whitelist or source expressions such as `'self'` or `'unsafe-inline'` will be ignored. See script-src for an example.
  StrictDynamic,
  /// Requires a sample of the violating code to be included in the violation report.
  ReportSample,
}

impl<'a> Sources<'a> {
  pub fn new_with(source: Source<'a>) -> Self {
    Sources(vec![source])
  }

  pub fn new() -> Self {
    Sources(vec![])
  }

  pub fn add_borrowed<'b>(&'b mut self, source: Source<'a>) -> &'b mut Self {
    self.0.push(source);
    self
  }

  pub fn add(mut self, source: Source<'a>) -> Self {
    self.0.push(source);
    self
  }
}

impl<'a> fmt::Display for Sources<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.len() < 1 {
      return write!(fmt, "'none'");
    }

    let mut formatted_string = String::new();

    for source in &self.0[0..self.0.len() - 1] {
      formatted_string.push_str(&source.to_string());
      formatted_string.push_str(" ");
    }

    formatted_string.push_str(&self.0[self.0.len() - 1].to_string());
    write!(fmt, "{}", formatted_string)
  }
}

impl<'a> fmt::Display for Source<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    write!(
      fmt,
      "{}",
      match self {
        Self::Host(s) => s,
        Self::Scheme(s) => {
          return write!(fmt, "{}:", s);
        }
        Self::Self_ => "'self'",
        Self::UnsafeEval => "'unsafe-eval'",
        Self::UnsafeHashes => "'unsafe-hashes'",
        Self::UnsafeInline => "'unsafe-inline'",
        Self::Nonce(s) => {
          return write!(fmt, "'nonce-{}'", s);
        }
        Self::Hash((algo, hash)) => {
          return write!(fmt, "'{}-{}'", algo, hash);
        }
        Self::StrictDynamic => "'strict-dynamic'",
        Self::ReportSample => "'report-sample'",
      }
    )
  }
}
