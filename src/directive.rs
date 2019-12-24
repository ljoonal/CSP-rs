use crate::{Plugins, ReportUris, SandboxAllowedList, Sources, SriFor, TrustedTypes, CSP};
use std::fmt;

#[derive(Debug, Clone)]
/// A CSP directive.
pub enum Directive<'a> {
  /// Restricts the URLs which can be used in a document's \<base> element.
  ///
  /// If this value is absent, then any URI is allowed. If this directive is absent, the user agent will use the value in the \<base> element.
  BaseUri(Sources<'a>),
  /// Prevents loading any assets using HTTP when the page is loaded using HTTPS.
  ///
  ///All mixed content resource requests are blocked, including both active and passive mixed content. This also applies to \<iframe> documents, ensuring the entire page is mixed content free.
  /// The upgrade-insecure-requests directive is evaluated before block-all-mixed-content and If the former is set, the latter is effectively a no-op. It is recommended to set one directive or the other – not both, unless you want to force HTTPS on older browsers that do not force it after a redirect to HTTP.
  BlockAllMixedContent,
  /// Defines the valid sources for web workers and nested browsing contexts loaded using elements such as \<frame> and \<iframe>.
  ///
  /// For workers, non-compliant requests are treated as fatal network errors by the user agent.
  ChildSrc(Sources<'a>),
  /// restricts the URLs which can be loaded using script interfaces. The APIs that are restricted are:
  ///
  /// - \<a> ping,
  /// - Fetch,
  /// - XMLHttpRequest,
  /// - WebSocket,
  /// - EventSource,
  /// - Navigator.sendBeacon().
  ///
  /// Note: connect-src 'self' does not resolve to websocket schemas in all browsers, more info: https://github.com/w3c/webappsec-csp/issues/7
  ConnectSrc(Sources<'a>),
  /// Serves as a fallback for the other CSP fetch directives.
  ///
  /// For each of the following directives that are absent, the user agent will look for the default-src directive and will use this value for it:
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
  /// Restricts the URLs which can be used as the target of a form submissions from a given context.
  ///
  /// Whether form-action should block redirects after a form submission is debated and browser implementations of this aspect are inconsistent (e.g. Firefox 57 doesn't block the redirects whereas Chrome 63 does).
  FormAction(Sources<'a>),
  /// specifies valid parents that may embed a page using \<frame>, \<iframe>, \<object>, \<embed>, or \<applet>.
  ///
  /// Setting this directive to 'none' is similar to X-Frame-Options: deny (which is also supported in older browsers).
  FrameAncestors(Sources<'a>),
  /// Specifies valid sources for nested browsing contexts loading using elements such as \<frame> and \<iframe>.
  FrameSrc(Sources<'a>),
  /// Specifies valid sources of images and favicons.
  ImgSrc(Sources<'a>),
  /// Specifies which manifest can be applied to the resource.
  ManifestSrc(Sources<'a>),
  /// Specifies valid sources for loading media using the \<audio> and \<video> elements.
  MediaSrc(Sources<'a>),
  /// restricts the URLs to which a document can initiate navigations by any means including \<form> (if form-action is not specified), \<a>, window.location, window.open, etc.
  ///
  /// This is an enforcement on what navigations this document initiates not on what this document is allowed to navigate to.
  ///
  /// Note: If the form-action directive is present, the navigate-to directive will not act on navigations that are form submissions.
  NavigateTo(Sources<'a>),
  /// specifies valid sources for the \<object>, \<embed>, and \<applet> elements.
  ///
  /// To set allowed types for \<object>, \<embed>, and \<applet> elements, use the PluginTypes.
  ///
  /// Elements controlled by object-src are perhaps coincidentally considered legacy HTML elements and aren't receiving new standardized features (such as the security attributes sandbox or allow for \<iframe>). Therefore it is recommended to restrict this fetch-directive (e.g. explicitly set object-src 'none' if possible).
  ObjectSrc(Sources<'a>),
  /// Restricts the set of plugins that can be embedded into a document by limiting the types of resources which can be loaded.
  ///
  /// Instantiation of an \<embed>, \<object> or \<applet> element will fail if:
  /// - the element to load does not declare a valid MIME type,
  /// - the declared type does not match one of specified types in the plugin-types directive,
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
  /// The directive has no effect in and of itself, but only gains meaning in combination with other directives.
  ReportTo(&'a str),
  /// Deprecated.
  ///
  /// Instructs the user agent to report attempts to violate the Content Security Policy. These violation reports consist of JSON documents sent via an HTTP POST request to the specified URI.
  ///
  /// This feature is no longer recommended. Though some browsers might still support it, it may have already been removed from the relevant web standards, may be in the process of being dropped, or may only be kept for compatibility purposes. Avoid using it, and update existing code if possible.
  ///
  /// Though the report-to directive is intended to replace the deprecated report-uri directive, report-to isn’t supported in most browsers yet. So for compatibility with current browsers while also adding forward compatibility when browsers get report-to support, you can specify both report-uri and report-to:
  /// ```text
  /// Content-Security-Policy: ...; report-uri https://endpoint.com; report-to groupname
  /// ```
  /// In browsers that support report-to, the report-uri directive will be ignored.
  ReportUri(ReportUris<'a>),
  /// Instructs the client to require the use of Subresource Integrity for scripts or styles on the page.
  RequireSriFor(SriFor),
  /// Enables a sandbox for the requested resource similar to the \<iframe> sandbox attribute.
  ///
  /// It applies restrictions to a page's actions including preventing popups, preventing the execution of plugins and scripts, and enforcing a same-origin policy.
  ///
  /// You can leave the SandboxAllowedList empty (`SandboxAllowedList::new_empty()`) to disallow everything.
  Sandbox(SandboxAllowedList),
  /// Specifies valid sources for JavaScript.
  ///
  /// This includes not only URLs loaded directly into \<script> elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
  ScriptSrc(Sources<'a>),
  /// Specifies valid sources for JavaScript.
  ///
  /// This includes not only URLs loaded directly into \<script> elements, but also things like inline script event handlers (onclick) and XSLT stylesheets which can trigger script execution.
  ScriptSrcAttr(Sources<'a>),
  /// Specifies valid sources for JavaScript \<script> elements, but not inline script event handlers like onclick.
  ScriptSrcElem(Sources<'a>),
  /// specifies valid sources for stylesheets.
  StyleSrc(Sources<'a>),
  /// Specifies valid sources for inline styles applied to individual DOM elements.
  StyleSrcAttr(Sources<'a>),
  /// Specifies valid sources for stylesheets \<style> elements and \<link> elements with rel="stylesheet".
  StyleSrcElem(Sources<'a>),
  /// Instructs user agents to restrict usage of known DOM XSS sinks to a predefined set of functions that only accept non-spoofable, typed values in place of strings.
  ///
  /// This allows authors to define rules guarding writing values to the DOM and thus reducing the DOM XSS attack surface to small, isolated parts of the web application codebase, facilitating their monitoring and code review. This directive declares a white-list of trusted type policy names created with TrustedTypes.createPolicy from Trusted Types API.
  TrustedTypes(TrustedTypes<'a>),
  /// Instructs user agents to treat all of a site's insecure URLs (those served over HTTP) as though they have been replaced with secure URLs (those served over HTTPS).
  ///
  /// This directive is intended for web sites with large numbers of insecure legacy URLs that need to be rewritten.
  ///
  /// The upgrade-insecure-requests directive is evaluated before block-all-mixed-content and if it is set, the latter is effectively a no-op. It is recommended to set either directive, but not both, unless you want to force HTTPS on older browsers that do not force it after a redirect to HTTP.
  /// The upgrade-insecure-requests directive will not ensure that users visiting your site via links on third-party sites will be upgraded to HTTPS for the top-level navigation and thus does not replace the Strict-Transport-Security (HSTS) header, which should still be set with an appropriate max-age to ensure that users are not subject to SSL stripping attacks.
  UpgradeInsecureRequests,
  /// Instructs user agents to restrict usage of known DOM XSS sinks to a predefined set of functions that only accept non-spoofable, typed values in place of strings.
  ///
  /// This allows authors to define rules guarding writing values to the DOM and thus reducing the DOM XSS attack surface to small, isolated parts of the web application codebase, facilitating their monitoring and code review. This directive declares a white-list of trusted type policy names created with TrustedTypes.createPolicy from Trusted Types API.
  WorkerSrc(Sources<'a>),
}

impl<'a> Into<CSP<'a>> for Directive<'a> {
  fn into(self) -> CSP<'a> {
    CSP::new_with(self)
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
      Self::ReportUri(s) => write!(fmt, "report-uri {}", s),
      Self::RequireSriFor(s) => write!(fmt, "require-sri-for {}", s),
      Self::Sandbox(s) => match s.len() {
        0 => write!(fmt, "sandbox"),
        _ => write!(fmt, "sandbox {}", s),
      },
      Self::ScriptSrc(s) => write!(fmt, "script-src {}", s),
      Self::ScriptSrcAttr(s) => write!(fmt, "script-src-attr {}", s),
      Self::ScriptSrcElem(s) => write!(fmt, "script-src-elem {}", s),
      Self::StyleSrc(s) => write!(fmt, "style-src {}", s),
      Self::StyleSrcAttr(s) => write!(fmt, "style-src-attr {}", s),
      Self::StyleSrcElem(s) => write!(fmt, "style-src-elem {}", s),
      Self::TrustedTypes(s) => write!(fmt, "trusted-types {}", s),
      Self::UpgradeInsecureRequests => write!(fmt, "upgrade-insecure-requests"),
      Self::WorkerSrc(s) => write!(fmt, "worker-src {}", s),
    }
  }
}
