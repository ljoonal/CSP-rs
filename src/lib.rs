//! This crate is a helper to quickly construct a CSP and then turn it into a
//! String.
//!
//! This library can help you when you don't want to remember some weird
//! formatting rules of CSP, and want to avoid typos. And it certainly can be
//! handy if you need to re-use things, for example a list of sources (just
//! .clone() them everywhere and you're good to go!).
//!
//! WARNING: this library does not care if you create invalid CSP rules, and
//! happily allows them and turns them into Strings. But it does force you to
//! use a typed structure, so it'll be harder to mess up than when manually
//! writing CSP. Another thing that this crate does not do: It does not do any
//! base64 or percent encoding or anything like that.
//!
//! # Example usage
//! ```rust
//! use csp::{CSP, Directive, Sources, Source};
//!
//! let csp = CSP::new()
//!   .push(Directive::ImgSrc(
//!     Sources::new_with(Source::Self_)
//!       .push(Source::Host("https://*.example.org"))
//!       .push(Source::Host("https://shields.io")),
//!   ))
//!   .push(Directive::ConnectSrc(
//!     Sources::new()
//!       .push(Source::Host("http://crates.io"))
//!       .push(Source::Scheme("https"))
//!       .push(Source::Self_),
//!   ))
//!   .push(Directive::StyleSrc(
//!     Sources::new_with(Source::Self_).push(Source::UnsafeInline),
//!   ))
//!   .push(Directive::ObjectSrc(Sources::new()));
//!
//! let csp_header = "Content-Security-Policy: ".to_owned() + &csp.to_string();
//! ```
//! # Copyright notice for this crate's docs:
//! Most of the comments for various CSP things are from [MDN](https://developer.mozilla.org/en-US/docs/MDN/About), so they licensed under [CC-BY-SA 2.5](https://creativecommons.org/licenses/by-sa/2.5/)
//! So attribution of most of the docs goes to [Mozilla Contributors](https://developer.mozilla.org/en-US/docs/MDN/Writing_guidelines/contributors.txt).
//!
//! Please go to MDN to read up to date docs, as these ones might not be up to
//! date.

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![deny(clippy::cargo)]
#![warn(missing_docs)]
#![deny(rustdoc::invalid_html_tags)]
#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]

use std::fmt;

#[derive(Debug, Default, Clone)]
/// The starting point for building a Content Security Policy.
///
/// You'll add [`Directive`] into this struct, and later on call `.to_string()`
/// on it to get it as a header compatible string. Doesn't include
/// content-security-policy: part in it though.
///
/// [`Directive`]: Directive
pub struct CSP<'a>(Vec<Directive<'a>>);

#[derive(Debug, Default, Clone)]
/// A struct to give source(s) to a [`Directive`] which might require it.
///
/// # Example usage
/// ```rust
/// use csp::{Sources, Source};
///
/// let sources = Sources::new().push(Source::Self_).push(Source::Scheme("data"));
///
/// assert_eq!(sources.to_string(), "'self' data:");
/// ```
///
/// [`Directive`]: Directive
pub struct Sources<'a>(Vec<Source<'a>>);

#[derive(Debug, Default, Clone)]
/// Used for `PluginTypes` [`Directive`].
///
/// # Example usage
/// ```rust
/// let flash = csp::Plugins::new().push(("application", "x-shockwave-flash"));
/// ```
///  to get `application/x-shockwave-flash`
///
/// [`Directive`]: Directive
pub struct Plugins<'a>(Vec<(&'a str, &'a str)>);

#[derive(Debug, Default, Clone)]
/// Used for `ReportUri` [`Directive`].
///
/// # Example usage
/// ```rust
/// let report_uris = csp::ReportUris::new().push("https://example.org/report");
/// ```
///
/// [`Directive`]: Directive
pub struct ReportUris<'a>(Vec<&'a str>);

#[derive(Debug, Default, Clone)]
/// Used for `Sandbox` [`Directive`].
///
/// [`Directive`]: Directive
pub struct SandboxAllowedList(Vec<SandboxAllow>);

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

#[derive(Debug, Clone)]
/// The source that a bunch of directives can have multiple of.
///
/// If nothing gets added, becomes 'none'.
pub enum Source<'a> {
  /// Internet hosts by name or IP address, as well as an optional URL scheme
  /// and/or port number.
  ///
  /// The site's address may include an optional leading wildcard (the
  /// asterisk character, '*'), and you may use a wildcard (again, '*') as the
  /// port number, indicating that all legal ports are valid for the source.
  /// Examples:
  /// - `http://*.example.com`: Matches all attempts to load from any subdomain
  ///   of example.com using the `http:` URL scheme.
  /// - `mail.example.com:443`: Matches all attempts to access port 443 on
  ///   mail.example.com.
  /// - `https://store.example.com`: Matches all attempts to access
  ///   store.example.com using https:.
  Host(&'a str),
  /// A schema such as 'http' or 'https'.
  ///
  ///  The colon is automatically added to the end. You can also specify data
  /// schemas (not recommended).
  /// - `data` Allows data: URIs to be used as a content source. This is
  ///   insecure; an attacker can also inject arbitrary data: URIs. Use this
  ///   sparingly and definitely not for scripts.
  /// - `mediastream` Allows `mediastream:` URIs to be used as a content source.
  /// - `blob` Allows `blob:` URIs to be used as a content source.
  /// - `filesystem` Allows `filesystem:` URIs to be used as a content source.
  Scheme(&'a str),
  /// Refers to the origin from which the protected document is being served,
  /// including the same URL scheme and port number.
  ///
  /// Some browsers specifically exclude `blob` and `filesystem` from source
  /// directives. Sites needing to allow these content types can specify them
  /// using the Data attribute.
  Self_,
  /// Allows the use of `eval()` and similar methods for creating code from
  /// strings.
  UnsafeEval,
  /// Allows the compilation and instantiation of WebAssembly.
  WasmUnsafeEval,
  /// Allows to enable specific inline event handlers. If you only need to
  /// allow inline event handlers and not inline `<script>` elements or
  /// `javascript:` URLs, this is a safer method compared to using the
  /// `unsafe-inline` expression.
  UnsafeHashes,
  /// Allows the use of inline resources, such as inline `<script>` elements,
  /// javascript: URLs, inline event handlers, and inline <\style> elements.
  UnsafeInline,
  /// A whitelist for specific inline scripts using a cryptographic nonce
  /// (number used once). The server must generate a unique nonce value each
  /// time it transmits a policy. It is critical to provide an unguessable
  /// nonce, as bypassing a resource’s policy is otherwise trivial. See unsafe
  /// inline script for an example. Specifying nonce makes a modern browser
  /// ignore `'unsafe-inline'` which could still be set for older browsers
  /// without nonce support.
  Nonce(&'a str),
  /// A sha256, sha384 or sha512 hash of scripts or styles. The use of this
  /// source consists of two portions separated by a dash: the encryption
  /// algorithm used to create the hash and the base64-encoded hash of the
  /// script or style. When generating the hash, don't include the `<script>`
  /// or `<style>` tags and note that capitalization and whitespace matter,
  /// including leading or trailing whitespace. See unsafe inline script for
  /// an example. In CSP 2.0 this applied only to inline scripts. CSP 3.0
  /// allows it in the case of `script-src` for external scripts.
  Hash((&'a str, &'a str)),
  /// The `strict-dynamic` source expression specifies that the trust
  /// explicitly given to a script present in the markup, by accompanying it
  /// with a nonce or a hash, shall be propagated to all the scripts loaded by
  /// that root script. At the same time, any whitelist or source expressions
  /// such as `'self'` or `'unsafe-inline'` will be ignored. See script-src
  /// for an example.
  StrictDynamic,
  /// Requires a sample of the violating code to be included in the violation
  /// report.
  ReportSample,
}

#[derive(Debug, Clone)]
/// Optionally used for the `Sandbox` directive. Not using it but using the
/// sandbox directive disallows everything that you could allow with the
/// optional values.
pub enum SandboxAllow {
  /// Allows for downloads to occur without a gesture from the user.
  DownloadsWithoutUserActivation,
  /// Allows the embedded browsing context to submit forms. If this keyword is
  /// not used, this operation is not allowed.
  Forms,
  /// Allows the embedded browsing context to open modal windows.
  Modals,
  /// Allows the embedded browsing context to disable the ability to lock the
  /// screen orientation.
  OrientationLock,
  /// Allows the embedded browsing context to use the Pointer Lock API.
  PointerLock,
  /// Allows popups (like from window.open, target="_blank", showModalDialog).
  /// If this keyword is not used, that functionality will silently fail.
  Popups,
  /// Allows a sandboxed document to open new windows without forcing the
  /// sandboxing flags upon them. This will allow, for example, a third-party
  /// advertisement to be safely sandboxed without forcing the same
  /// restrictions upon a landing page.
  PopupsToEscapeSandbox,
  /// Allows embedders to have control over whether an iframe can start a
  /// presentation session.
  Presentation,
  /// Allows the content to be treated as being from its normal origin. If
  /// this keyword is not used, the embedded content is treated as being from
  /// a unique origin.
  SameOrigin,
  /// Allows the embedded browsing context to run scripts (but not create
  /// pop-up windows). If this keyword is not used, this operation is not
  /// allowed.
  Scripts,
  /// Lets the resource request access to the parent's storage capabilities
  /// with the Storage Access API.
  StorageAccessByUserActivation,
  /// Allows the embedded browsing context to navigate (load) content to the
  /// top-level browsing context. If this keyword is not used, this operation
  /// is not allowed.
  TopNavigation,
  /// Lets the resource navigate the top-level browsing context, but only if
  /// initiated by a user gesture.
  TopNavigationByUserActivation,
}

#[derive(Debug, Clone)]
/// A CSP directive.
pub enum Directive<'a> {
  /// Restricts the URLs which can be used in a document's `<base>` element.
  ///
  /// If this value is absent, then any URI is allowed. If this directive is
  /// absent, the user agent will use the value in the `<base>` element.
  BaseUri(Sources<'a>),
  /// Prevents loading any assets using HTTP when the page is loaded using
  /// HTTPS.
  ///
  ///All mixed content resource requests are blocked, including both active
  /// and passive mixed content. This also applies to `<iframe>` documents,
  /// ensuring the entire page is mixed content free.
  /// The upgrade-insecure-requests directive is evaluated before
  /// block-all-mixed-content and If the former is set, the latter is
  /// effectively a no-op. It is recommended to set one directive or the other
  /// – not both, unless you want to force HTTPS on older browsers that do not
  /// force it after a redirect to HTTP.
  BlockAllMixedContent,
  /// Defines the valid sources for web workers and nested browsing contexts
  /// loaded using elements such as `<frame>` and `<iframe>`.
  ///
  /// For workers, non-compliant requests are treated as fatal network errors
  /// by the user agent.
  ChildSrc(Sources<'a>),
  /// restricts the URLs which can be loaded using script interfaces. The APIs
  /// that are restricted are:
  ///
  /// - `<a>` ping,
  /// - Fetch,
  /// - XMLHttpRequest,
  /// - WebSocket,
  /// - EventSource,
  /// - Navigator.sendBeacon().
  ///
  /// Note: connect-src 'self' does not resolve to websocket schemas in all browsers, more info: <https://github.com/w3c/webappsec-csp/issues/7>
  ConnectSrc(Sources<'a>),
  /// Serves as a fallback for the other CSP fetch directives.
  ///
  /// For each of the following directives that are absent, the user agent
  /// will look for the default-src directive and will use this value for it:
  /// - child-src
  /// - connect-src
  /// - font-src
  /// - frame-src
  /// - img-src
  /// - manifest-src
  /// - media-src
  /// - object-src
  /// - prefetch-src
  /// - script-src
  /// - script-src-elem
  /// - script-src-attr
  /// - style-src
  /// - style-src-elem
  /// - style-src-attr
  /// - worker-src
  DefaultSrc(Sources<'a>),
  /// Specifies valid sources for fonts loaded using @font-face.
  FontSrc(Sources<'a>),
  /// Restricts the URLs which can be used as the target of a form submissions
  /// from a given context.
  ///
  /// Whether form-action should block redirects after a form submission is
  /// debated and browser implementations of this aspect are inconsistent
  /// (e.g. Firefox 57 doesn't block the redirects whereas Chrome 63 does).
  FormAction(Sources<'a>),
  /// specifies valid parents that may embed a page using `<frame>`, `<iframe>`,
  /// `<object>`, `<embed>`, or `<applet>`.
  ///
  /// Setting this directive to 'none' is similar to X-Frame-Options: deny
  /// (which is also supported in older browsers).
  FrameAncestors(Sources<'a>),
  /// Specifies valid sources for nested browsing contexts loading using
  /// elements such as `<frame>` and `<iframe>`.
  FrameSrc(Sources<'a>),
  /// Specifies valid sources of images and favicons.
  ImgSrc(Sources<'a>),
  /// Specifies which manifest can be applied to the resource.
  ManifestSrc(Sources<'a>),
  /// Specifies valid sources for loading media using the `<audio>` and
  /// `<video>` elements.
  MediaSrc(Sources<'a>),
  /// restricts the URLs to which a document can initiate navigations by any
  /// means including `<form>` (if form-action is not specified), `<a>`,
  /// window.location, window.open, etc.
  ///
  /// This is an enforcement on what navigations this document initiates not
  /// on what this document is allowed to navigate to.
  ///
  /// Note: If the form-action directive is present, the navigate-to directive
  /// will not act on navigations that are form submissions.
  NavigateTo(Sources<'a>),
  /// specifies valid sources for the `<object>`, `<embed>`, and `<applet>`
  /// elements.
  ///
  /// To set allowed types for `<object>`, `<embed>`, and `<applet>` elements,
  /// use the PluginTypes.
  ///
  /// Elements controlled by object-src are perhaps coincidentally considered
  /// legacy HTML elements and aren't receiving new standardized features
  /// (such as the security attributes sandbox or allow for `<iframe>`).
  /// Therefore it is recommended to restrict this fetch-directive (e.g.
  /// explicitly set object-src 'none' if possible).
  ObjectSrc(Sources<'a>),
  /// Restricts the set of plugins that can be embedded into a document by
  /// limiting the types of resources which can be loaded.
  ///
  /// Instantiation of an `<embed>`, `<object>` or `<applet>` element will fail
  /// if:
  /// - the element to load does not declare a valid MIME type,
  /// - the declared type does not match one of specified types in the
  ///   plugin-types directive,
  /// - the fetched resource does not match the declared type.
  PluginTypes(Plugins<'a>),
  /// Specifies valid resources that may be prefetched or prerendered.
  PrefetchSrc(Sources<'a>),
  /// Instructs the user agent to store reporting endpoints for an origin.
  ///
  /// ```text
  /// Content-Security-Policy: ...; report-to groupname
  /// ```
  ///
  /// The directive has no effect in and of itself, but only gains meaning in
  /// combination with other directives.
  ReportTo(&'a str),
  /// Deprecated.
  ///
  /// Instructs the user agent to report attempts to violate the Content
  /// Security Policy. These violation reports consist of JSON documents sent
  /// via an HTTP POST request to the specified URI.
  ///
  /// This feature is no longer recommended. Though some browsers might still
  /// support it, it may have already been removed from the relevant web
  /// standards, may be in the process of being dropped, or may only be kept
  /// for compatibility purposes. Avoid using it, and update existing code if
  /// possible.
  ///
  /// Though the report-to directive is intended to replace the deprecated
  /// report-uri directive, report-to isn’t supported in most browsers yet. So
  /// for compatibility with current browsers while also adding forward
  /// compatibility when browsers get report-to support, you can specify both
  /// report-uri and report-to:
  ///
  /// > `Content-Security-Policy: ...; report-uri <https://endpoint.com>;
  /// > report-to groupname`
  ///
  /// In browsers that support report-to, the report-uri directive will be
  /// ignored.
  ReportUri(ReportUris<'a>),
  /// Instructs the client to require the use of Subresource Integrity for
  /// scripts or styles on the page.
  RequireSriFor(SriFor),
  /// Enables a sandbox for the requested resource similar to the `<iframe>`
  /// sandbox attribute.
  ///
  /// It applies restrictions to a page's actions including preventing popups,
  /// preventing the execution of plugins and scripts, and enforcing a
  /// same-origin policy.
  ///
  /// You can leave the SandboxAllowedList empty
  /// (`SandboxAllowedList::new_empty()`) to disallow everything.
  Sandbox(SandboxAllowedList),
  /// Specifies valid sources for JavaScript.
  ///
  /// This includes not only URLs loaded directly into `<script>` elements, but
  /// also things like inline script event handlers (onclick) and XSLT
  /// stylesheets which can trigger script execution.
  ScriptSrc(Sources<'a>),
  /// Specifies valid sources for JavaScript.
  ///
  /// This includes not only URLs loaded directly into `<script>` elements, but
  /// also things like inline script event handlers (onclick) and XSLT
  /// stylesheets which can trigger script execution.
  ScriptSrcAttr(Sources<'a>),
  /// Specifies valid sources for JavaScript `<script>` elements, but not
  /// inline script event handlers like onclick.
  ScriptSrcElem(Sources<'a>),
  /// specifies valid sources for stylesheets.
  StyleSrc(Sources<'a>),
  /// Specifies valid sources for inline styles applied to individual DOM
  /// elements.
  StyleSrcAttr(Sources<'a>),
  /// Specifies valid sources for stylesheets `<style>` elements and `<link>`
  /// elements with rel="stylesheet".
  StyleSrcElem(Sources<'a>),
  /// Instructs user agents to restrict usage of known DOM XSS sinks to a
  /// predefined set of functions that only accept non-spoofable, typed values
  /// in place of strings.
  ///
  /// This allows authors to define rules guarding writing values to the DOM
  /// and thus reducing the DOM XSS attack surface to small, isolated parts of
  /// the web application codebase, facilitating their monitoring and code
  /// review. This directive declares a white-list of trusted type policy
  /// names created with TrustedTypes.createPolicy from Trusted Types API.
  TrustedTypes(Vec<&'a str>),
  /// Instructs user agents to treat all of a site's insecure URLs (those
  /// served over HTTP) as though they have been replaced with secure URLs
  /// (those served over HTTPS).
  ///
  /// This directive is intended for web sites with large numbers of insecure
  /// legacy URLs that need to be rewritten.
  ///
  /// The upgrade-insecure-requests directive is evaluated before
  /// block-all-mixed-content and if it is set, the latter is effectively a
  /// no-op. It is recommended to set either directive, but not both, unless
  /// you want to force HTTPS on older browsers that do not force it after a
  /// redirect to HTTP. The upgrade-insecure-requests directive will not
  /// ensure that users visiting your site via links on third-party sites will
  /// be upgraded to HTTPS for the top-level navigation and thus does not
  /// replace the Strict-Transport-Security (HSTS) header, which should still
  /// be set with an appropriate max-age to ensure that users are not subject
  /// to SSL stripping attacks.
  UpgradeInsecureRequests,
  /// Instructs user agents to restrict usage of known DOM XSS sinks to a
  /// predefined set of functions that only accept non-spoofable, typed values
  /// in place of strings.
  ///
  /// This allows authors to define rules guarding writing values to the DOM
  /// and thus reducing the DOM XSS attack surface to small, isolated parts of
  /// the web application codebase, facilitating their monitoring and code
  /// review. This directive declares a white-list of trusted type policy
  /// names created with TrustedTypes.createPolicy from Trusted Types API.
  WorkerSrc(Sources<'a>),
}

impl<'a> CSP<'a> {
  #[must_use]
  /// Creates a new empty CSP
  pub fn new() -> Self {
    Self::default()
  }

  #[must_use]
  /// Creates a new CSP with a given directive
  pub fn new_with(directive: Directive<'a>) -> Self {
    Self(vec![directive])
  }

  #[deprecated(since = "1.0.0", note = "please use `push_borrowed` instead")]
  #[allow(missing_docs)]
  pub fn add_borrowed<'b>(&'b mut self, directive: Directive<'a>) -> &'b mut Self {
    self.push_borrowed(directive);
    self
  }

  /// Pushes a directive to the end of the borrowed CSP
  pub fn push_borrowed<'b>(&'b mut self, directive: Directive<'a>) -> &'b mut Self {
    self.0.push(directive);
    self
  }

  #[allow(clippy::should_implement_trait)]
  #[deprecated(since = "1.0.0", note = "please use `push` instead")]
  #[must_use]
  #[allow(missing_docs)]
  pub fn add(self, directive: Directive<'a>) -> Self {
    self.push(directive)
  }

  #[must_use]
  /// Pushes a directive to the end of the CSP
  pub fn push(mut self, directive: Directive<'a>) -> Self {
    self.0.push(directive);
    self
  }
}

impl<'a> Sources<'a> {
  #[must_use]
  /// Creates a new empty Sources
  pub const fn new() -> Self {
    Self(vec![])
  }

  #[must_use]
  /// Creates new Sources with a source
  pub fn new_with(source: Source<'a>) -> Self {
    Self(vec![source])
  }

  #[deprecated(since = "1.0.0", note = "please use `push_borrowed` instead")]
  #[allow(missing_docs)]
  pub fn add_borrowed<'b>(&'b mut self, source: Source<'a>) -> &'b mut Self {
    self.push_borrowed(source);
    self
  }

  /// Pushes a source to the end of the borrowed Sources
  pub fn push_borrowed<'b>(&'b mut self, source: Source<'a>) -> &'b mut Self {
    self.0.push(source);
    self
  }

  #[allow(clippy::should_implement_trait)]
  #[deprecated(since = "1.0.0", note = "please use `push` instead")]
  #[must_use]
  #[allow(missing_docs)]
  pub fn add(self, source: Source<'a>) -> Self {
    self.push(source)
  }

  #[must_use]
  /// Pushes a source to the end of the Sources
  pub fn push(mut self, source: Source<'a>) -> Self {
    self.0.push(source);
    self
  }
}

impl<'a> Plugins<'a> {
  #[must_use]
  /// Creates a new Plugins with a plugin
  pub fn new_with(plugin: (&'a str, &'a str)) -> Self {
    Self(vec![plugin])
  }

  #[must_use]
  /// Creates a new empty plugins
  pub const fn new() -> Self {
    Self(vec![])
  }

  #[deprecated(since = "1.0.0", note = "please use `push_borrowed` instead")]
  #[allow(missing_docs)]
  pub fn add_borrowed<'b>(&'b mut self, plugin: (&'a str, &'a str)) -> &'b mut Self {
    self.push_borrowed(plugin);
    self
  }

  /// Pushes a plugin to the end of the borrowed Plugins
  pub fn push_borrowed<'b>(&'b mut self, plugin: (&'a str, &'a str)) -> &'b mut Self {
    self.0.push(plugin);
    self
  }

  #[allow(clippy::should_implement_trait)]
  #[deprecated(since = "1.0.0", note = "please use `push` instead")]
  #[must_use]
  #[allow(missing_docs)]
  pub fn add(self, plugin: (&'a str, &'a str)) -> Self {
    self.push(plugin)
  }

  #[must_use]
  /// Pushes a plugin to the end of the Plugins
  pub fn push(mut self, plugin: (&'a str, &'a str)) -> Self {
    self.0.push(plugin);
    self
  }
}

impl SandboxAllowedList {
  #[must_use]
  /// Creates a new `SandboxAllowedList` with only a certain sandbox allowance
  pub fn new_with(sandbox_allow: SandboxAllow) -> Self {
    Self(vec![sandbox_allow])
  }

  #[must_use]
  /// Creates a new empty `SandboxAllowedList`
  pub const fn new() -> Self {
    Self(vec![])
  }

  #[deprecated(since = "1.0.0", note = "please use `push_borrowed` instead")]
  #[allow(missing_docs)]
  pub fn add_borrowed(&'_ mut self, sandbox_allow: SandboxAllow) -> &'_ mut Self {
    self.push_borrowed(sandbox_allow);
    self
  }

  /// Pushes a sandbox allow type to the end of the borrowed
  /// `SandboxAllowedList`
  pub fn push_borrowed(&'_ mut self, sandbox_allow: SandboxAllow) -> &'_ mut Self {
    self.0.push(sandbox_allow);
    self
  }

  #[allow(clippy::should_implement_trait)]
  #[deprecated(since = "1.0.0", note = "please use `push` instead")]
  #[must_use]
  #[allow(missing_docs)]
  pub fn add(self, sandbox_allow: SandboxAllow) -> Self {
    self.push(sandbox_allow)
  }

  #[must_use]
  /// Pushes a sandbox allow type to the end of the `SandboxAllowedList`
  pub fn push(mut self, sandbox_allow: SandboxAllow) -> Self {
    self.0.push(sandbox_allow);
    self
  }
}

impl<'a> ReportUris<'a> {
  #[must_use]
  /// Creates a new `ReportUris` with a certain uri
  pub fn new_with(report_uri: &'a str) -> Self {
    ReportUris(vec![report_uri])
  }

  #[must_use]
  /// Creates a new empty `ReportUris`
  pub const fn new() -> Self {
    ReportUris(vec![])
  }

  #[deprecated(since = "1.0.0", note = "please use `push_borrowed` instead")]
  #[allow(missing_docs)]
  pub fn add_borrowed<'b>(&'b mut self, report_uri: &'a str) -> &'b mut Self {
    self.push_borrowed(report_uri);
    self
  }

  /// Pushes a report uri to the end of the borrowed `ReportUris`
  pub fn push_borrowed<'b>(&'b mut self, report_uri: &'a str) -> &'b mut Self {
    self.0.push(report_uri);
    self
  }

  #[allow(clippy::should_implement_trait)]
  #[deprecated(since = "1.0.0", note = "please use `push` instead")]
  #[must_use]
  #[allow(missing_docs)]
  pub fn add(self, report_uri: &'a str) -> Self {
    self.push(report_uri)
  }

  #[must_use]
  /// Pushes a report uri to the end of the `ReportUris`
  pub fn push(mut self, report_uri: &'a str) -> Self {
    self.0.push(report_uri);
    self
  }
}

impl<'a> fmt::Display for Source<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::Host(s) => write!(fmt, "{}", s),
      Self::Scheme(s) => write!(fmt, "{}:", s),
      Self::Self_ => write!(fmt, "'self'"),
      Self::UnsafeEval => write!(fmt, "'unsafe-eval'"),
      Self::WasmUnsafeEval => write!(fmt, "'wasm-unsafe-eval'"),
      Self::UnsafeHashes => write!(fmt, "'unsafe-hashes'"),
      Self::UnsafeInline => write!(fmt, "'unsafe-inline'"),
      Self::Nonce(s) => write!(fmt, "'nonce-{}'", s),
      Self::Hash((algo, hash)) => write!(fmt, "'{}-{}'", algo, hash),
      Self::StrictDynamic => write!(fmt, "'strict-dynamic'"),
      Self::ReportSample => write!(fmt, "'report-sample'"),
    }
  }
}

impl fmt::Display for SandboxAllow {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::DownloadsWithoutUserActivation => {
        write!(fmt, "allow-downloads-without-user-activation")
      }
      Self::Forms => write!(fmt, "allow-forms"),
      Self::Modals => write!(fmt, "allow-modals"),
      Self::OrientationLock => write!(fmt, "allow-orientation-lock"),
      Self::PointerLock => write!(fmt, "allow-pointer-lock"),
      Self::Popups => write!(fmt, "allow-popups"),
      Self::PopupsToEscapeSandbox => write!(fmt, "allow-popups-to-escape-sandbox"),
      Self::Presentation => write!(fmt, "allow-presentation"),
      Self::SameOrigin => write!(fmt, "allow-same-origin"),
      Self::Scripts => write!(fmt, "allow-scripts"),
      Self::StorageAccessByUserActivation => {
        write!(fmt, "allow-storage-access-by-user-activation")
      }
      Self::TopNavigation => write!(fmt, "allow-top-navigation"),
      Self::TopNavigationByUserActivation => {
        write!(fmt, "allow-top-navigation-by-user-activation")
      }
    }
  }
}

impl fmt::Display for SriFor {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::Script => write!(fmt, "script"),
      Self::Style => write!(fmt, "style"),
      Self::ScriptStyle => write!(fmt, "script style"),
    }
  }
}

impl<'a> fmt::Display for Directive<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::BaseUri(s) => write!(fmt, "base-uri {}", s),
      Self::BlockAllMixedContent => write!(fmt, "block-all-mixed-content"),
      Self::ChildSrc(s) => write!(fmt, "child-src {}", s),
      Self::ConnectSrc(s) => write!(fmt, "connect-src {}", s),
      Self::DefaultSrc(s) => write!(fmt, "default-src {}", s),
      Self::FontSrc(s) => write!(fmt, "font-src {}", s),
      Self::FormAction(s) => write!(fmt, "form-action {}", s),
      Self::FrameAncestors(s) => write!(fmt, "frame-ancestors {}", s),
      Self::FrameSrc(s) => write!(fmt, "frame-src {}", s),
      Self::ImgSrc(s) => write!(fmt, "img-src {}", s),
      Self::ManifestSrc(s) => write!(fmt, "manifest-src {}", s),
      Self::MediaSrc(s) => write!(fmt, "media-src {}", s),
      Self::NavigateTo(s) => write!(fmt, "navigate-to {}", s),
      Self::ObjectSrc(s) => write!(fmt, "object-src {}", s),
      Self::PluginTypes(s) => write!(fmt, "plugin-types {}", s),
      Self::PrefetchSrc(s) => write!(fmt, "prefetch-src {}", s),
      Self::ReportTo(s) => write!(fmt, "report-to {}", s),
      Self::ReportUri(uris) => {
        write!(fmt, "report-uri ")?;

        for uri in &uris.0[0..uris.0.len() - 1] {
          write!(fmt, "{} ", uri)?;
        }

        let last = uris.0[uris.0.len() - 1];
        write!(fmt, "{}", last)
      }
      Self::RequireSriFor(s) => write!(fmt, "require-sri-for {}", s),
      Self::Sandbox(s) => {
        if s.0.is_empty() {
          write!(fmt, "sandbox")
        } else {
          write!(fmt, "sandbox {}", s)
        }
      }
      Self::ScriptSrc(s) => write!(fmt, "script-src {}", s),
      Self::ScriptSrcAttr(s) => write!(fmt, "script-src-attr {}", s),
      Self::ScriptSrcElem(s) => write!(fmt, "script-src-elem {}", s),
      Self::StyleSrc(s) => write!(fmt, "style-src {}", s),
      Self::StyleSrcAttr(s) => write!(fmt, "style-src-attr {}", s),
      Self::StyleSrcElem(s) => write!(fmt, "style-src-elem {}", s),
      Self::TrustedTypes(trusted_types) => {
        write!(fmt, "trusted-types ")?;

        for trusted_type in &trusted_types[0..trusted_types.len() - 1] {
          write!(fmt, "{} ", trusted_type)?;
        }

        let last = trusted_types[trusted_types.len() - 1];
        write!(fmt, "{}", last)
      }
      Self::UpgradeInsecureRequests => write!(fmt, "upgrade-insecure-requests"),
      Self::WorkerSrc(s) => write!(fmt, "worker-src {}", s),
    }
  }
}

impl<'a> fmt::Display for Plugins<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.is_empty() {
      return write!(fmt, "");
    }

    for plugin in &self.0[0..self.0.len() - 1] {
      write!(fmt, "{}/{} ", plugin.0, plugin.1)?;
    }

    let last = &self.0[self.0.len() - 1];
    write!(fmt, "{}/{}", last.0, last.1)
  }
}

impl<'a> fmt::Display for Sources<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.is_empty() {
      return write!(fmt, "'none'");
    }

    for source in &self.0[0..self.0.len() - 1] {
      write!(fmt, "{} ", source)?;
    }

    let last = &self.0[self.0.len() - 1];
    write!(fmt, "{}", last)
  }
}

impl fmt::Display for SandboxAllowedList {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.is_empty() {
      return write!(fmt, "");
    }

    for directive in &self.0[0..self.0.len() - 1] {
      write!(fmt, "{} ", directive)?;
    }

    let last = &self.0[self.0.len() - 1];
    write!(fmt, "{}", last)
  }
}

impl<'a> fmt::Display for CSP<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.is_empty() {
      return write!(fmt, "");
    }

    for directive in &self.0[0..self.0.len() - 1] {
      write!(fmt, "{}; ", directive)?;
    }

    let last = &self.0[self.0.len() - 1];
    write!(fmt, "{}", last)
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  /// Tests combining different Directives and sources, and makes sure that
  /// spaces and semicolons are inserted correctly.
  fn large_csp() {
    let font_src = Source::Host("https://cdn.example.org");

    let mut csp = CSP::new()
      .push(Directive::ImgSrc(
        Sources::new_with(Source::Self_)
          .push(Source::Scheme("https"))
          .push(Source::Host("http://shields.io")),
      ))
      .push(Directive::ConnectSrc(
        Sources::new().push(Source::Host("https://crates.io")).push(Source::Self_),
      ))
      .push(Directive::StyleSrc(
        Sources::new_with(Source::Self_)
          .push(Source::UnsafeInline)
          .push(font_src.clone()),
      ));

    csp.push_borrowed(Directive::FontSrc(Sources::new_with(font_src)));

    println!("{}", csp);

    let csp = csp.to_string();

    assert_eq!(
      csp,
      "img-src 'self' https: http://shields.io; connect-src https://crates.io 'self'; style-src 'self' 'unsafe-inline' https://cdn.example.org; font-src https://cdn.example.org"
    );
  }

  #[test]
  /// Tests all the possible source variations.
  fn all_sources() {
    let csp = CSP::new().push(Directive::ScriptSrc(
      Sources::new()
        .push(Source::Hash(("sha256", "1234a")))
        .push(Source::Nonce("5678b"))
        .push(Source::ReportSample)
        .push(Source::StrictDynamic)
        .push(Source::UnsafeEval)
        .push(Source::WasmUnsafeEval)
        .push(Source::UnsafeHashes)
        .push(Source::UnsafeInline)
        .push(Source::Scheme("data"))
        .push(Source::Host("https://example.org"))
        .push(Source::Self_),
    ));

    assert_eq!(
      csp.to_string(),
      "script-src 'sha256-1234a' 'nonce-5678b' 'report-sample' 'strict-dynamic' 'unsafe-eval' 'wasm-unsafe-eval' 'unsafe-hashes' 'unsafe-inline' data: https://example.org 'self'"
    );
  }

  #[test]
  fn empty_values() {
    let csp = CSP::new();

    assert_eq!(csp.to_string(), "");

    let csp = CSP::new().push(Directive::ImgSrc(Sources::new()));

    assert_eq!(csp.to_string(), "img-src 'none'");
  }

  #[test]
  fn sandbox() {
    let csp = CSP::new().push(Directive::Sandbox(SandboxAllowedList::new()));

    assert_eq!(csp.to_string(), "sandbox");

    let csp = CSP::new()
      .push(Directive::Sandbox(SandboxAllowedList::new().push(SandboxAllow::Scripts)));

    assert_eq!(csp.to_string(), "sandbox allow-scripts");
    assert_eq!(
      csp.to_string(),
      "sandbox ".to_owned() + &SandboxAllow::Scripts.to_string()
    );
  }

  #[test]
  fn special() {
    let mut csp = CSP::new();
    let sri_directive = Directive::RequireSriFor(SriFor::Script);

    csp.push_borrowed(sri_directive);

    assert_eq!(csp.to_string(), "require-sri-for script");

    let csp = CSP::new_with(Directive::BlockAllMixedContent);
    assert_eq!(csp.to_string(), "block-all-mixed-content");

    let csp = CSP::new_with(Directive::PluginTypes(
      Plugins::new().push(("application", "x-java-applet")),
    ));
    assert_eq!(csp.to_string(), "plugin-types application/x-java-applet");

    let csp = CSP::new_with(Directive::ReportTo("endpoint-1"));
    assert_eq!(csp.to_string(), "report-to endpoint-1");

    let csp = CSP::new_with(Directive::ReportUri(
      ReportUris::new_with("https://r1.example.org").push("https://r2.example.org"),
    ));
    assert_eq!(
      csp.to_string(),
      "report-uri https://r1.example.org https://r2.example.org"
    );

    let csp = CSP::new_with(Directive::TrustedTypes(vec!["hello", "hello2"]));
    assert_eq!(csp.to_string(), "trusted-types hello hello2");

    let csp = CSP::new_with(Directive::UpgradeInsecureRequests);
    assert_eq!(csp.to_string(), "upgrade-insecure-requests");
  }
}
