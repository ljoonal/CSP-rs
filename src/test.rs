use super::*;

#[test]
/// Tests combining different Directives and sources, and makes sure that spaces and semicolons are inserted correctly.
fn large_csp() {
  let font_src = Source::Host("https://cdn.example.org");

  let mut csp = CSP::new()
    .add(Directive::ImgSrc(
      Sources::new_with(Source::Self_)
        .add(Source::Scheme("https"))
        .add(Source::Host("http://shields.io")),
    ))
    .add(Directive::ConnectSrc(
      Sources::new()
        .add(Source::Host("https://crates.io"))
        .add(Source::Self_),
    ))
    .add(Directive::StyleSrc(
      Sources::new_with(Source::Self_)
        .add(Source::UnsafeInline)
        .add(font_src.clone()),
    ));

  csp.add_borrowed(Directive::FontSrc(Sources::new_with(font_src)));

  println!("{}", csp);

  let csp = csp.to_string();

  assert_eq!(csp.to_string(), "img-src 'self' https: http://shields.io; connect-src https://crates.io 'self'; style-src 'self' 'unsafe-inline' https://cdn.example.org; font-src https://cdn.example.org");
}

#[test]
/// Tests all the possible source variations.
fn all_sources() {
  let csp = CSP::new().add(Directive::ScriptSrc(
    Sources::new()
      .add(Source::Hash(("sha256", "1234a")))
      .add(Source::Nonce("5678b"))
      .add(Source::ReportSample)
      .add(Source::StrictDynamic)
      .add(Source::UnsafeEval)
      .add(Source::UnsafeHashes)
      .add(Source::UnsafeInline)
      .add(Source::Scheme("data"))
      .add(Source::Host("https://example.org"))
      .add(Source::Self_),
  ));

  assert_eq!(
      csp.to_string(),
      "script-src 'sha256-1234a' 'nonce-5678b' 'report-sample' 'strict-dynamic' 'unsafe-eval' 'unsafe-hashes' 'unsafe-inline' data: https://example.org 'self'"
    );
}

#[test]
fn empty_values() {
  let csp = CSP::new();

  assert_eq!(csp.to_string(), "");

  let csp = CSP::new().add(Directive::ImgSrc(Sources::new()));

  assert_eq!(csp.to_string(), "img-src 'none'");
}

#[test]
fn sandbox() {
  let csp = CSP::new().add(Directive::Sandbox(SandboxAllowedList::new()));

  assert_eq!(csp.to_string(), "sandbox");

  let csp = CSP::new().add(Directive::Sandbox(
    SandboxAllowedList::new().add(SandboxAllow::Scripts),
  ));

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

  csp.add_borrowed(sri_directive);

  assert_eq!(csp.to_string(), "require-sri-for script");

  let csp = CSP::new_with(Directive::BlockAllMixedContent);
  assert_eq!(csp.to_string(), "block-all-mixed-content");

  let csp = CSP::new_with(Directive::PluginTypes(Plugins::new_with((
    "application",
    "x-java-applet",
  ))));
  assert_eq!(csp.to_string(), "plugin-types application/x-java-applet");

  let csp = CSP::new_with(Directive::ReportTo("endpoint-1"));
  assert_eq!(csp.to_string(), "report-to endpoint-1");

  let csp = CSP::new_with(Directive::ReportUri(
    ReportUris::new_with("https://r1.example.org").add("https://r2.example.org"),
  ));
  assert_eq!(
    csp.to_string(),
    "report-uri https://r1.example.org https://r2.example.org"
  );

  let csp = CSP::new_with(Directive::TrustedTypes(TrustedTypes::new_with("hello")));
  assert_eq!(csp.to_string(), "trusted-types hello hello2");

  let csp = CSP::new_with(Directive::UpgradeInsecureRequests);
  assert_eq!(csp.to_string(), "upgrade-insecure-requests");
}
