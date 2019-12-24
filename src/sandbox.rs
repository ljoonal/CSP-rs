use std::fmt;

#[derive(Debug, Clone)]
/// Used for `Sandbox` [`Directive`].
///
/// [`Directive`]: Directive
pub struct SandboxAllowedList(Vec<SandboxAllow>);

#[derive(Debug, Clone)]
/// Optionally used for the `Sandbox` directive. Not uing it but using the sandbox directive disallows everything that you could allow with the optional values.
pub enum SandboxAllow {
  /// Allows for downloads to occur without a gesture from the user.
  DownloadsWithoutUserActivation,
  /// Allows the embedded browsing context to submit forms. If this keyword is not used, this operation is not allowed.
  Forms,
  /// Allows the embedded browsing context to open modal windows.
  Modals,
  /// Allows the embedded browsing context to disable the ability to lock the screen orientation.
  OrientationLock,
  /// Allows the embedded browsing context to use the Pointer Lock API.
  PointerLock,
  /// Allows popups (like from window.open, target="_blank", showModalDialog). If this keyword is not used, that functionality will silently fail.
  Popups,
  /// Allows a sandboxed document to open new windows without forcing the sandboxing flags upon them. This will allow, for example, a third-party advertisement to be safely sandboxed without forcing the same restrictions upon a landing page.
  PopupsToEscapeSandbox,
  /// Allows embedders to have control over whether an iframe can start a presentation session.
  Presentation,
  /// Allows the content to be treated as being from its normal origin. If this keyword is not used, the embedded content is treated as being from a unique origin.
  SameOrigin,
  /// Allows the embedded browsing context to run scripts (but not create pop-up windows). If this keyword is not used, this operation is not allowed.
  Scripts,
  /// Lets the resource request access to the parent's storage capabilities with the Storage Access API.
  StorageAccessByUserActivation,
  /// Allows the embedded browsing context to navigate (load) content to the top-level browsing context. If this keyword is not used, this operation is not allowed.
  TopNavigation,
  /// Lets the resource navigate the top-level browsing context, but only if initiated by a user gesture.
  TopNavigationByUserActivation,
}

impl SandboxAllowedList {
  pub fn new_with(sandbox_allow: SandboxAllow) -> Self {
    SandboxAllowedList(vec![sandbox_allow])
  }

  pub fn new() -> Self {
    SandboxAllowedList(vec![])
  }

  pub fn add_borrowed<'b>(&'b mut self, sandbox_allow: SandboxAllow) -> &'b mut Self {
    self.0.push(sandbox_allow);
    self
  }

  pub fn add(mut self, sandbox_allow: SandboxAllow) -> Self {
    self.0.push(sandbox_allow);
    self
  }

  pub fn get<'b>(&'b self) -> &'b Vec<SandboxAllow> {
    &self.0
  }

  pub fn len(&self) -> usize {
    self.0.len()
  }
}

impl Into<SandboxAllowedList> for SandboxAllow {
  fn into(self) -> SandboxAllowedList {
    SandboxAllowedList::new_with(self)
  }
}

impl fmt::Display for SandboxAllowedList {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.0.len() < 1 {
      return write!(fmt, "");
    }

    let mut formatted_string = String::new();

    for directive in &self.0[0..self.0.len() - 1] {
      formatted_string.push_str(&directive.to_string());
      formatted_string.push_str(" ");
    }

    formatted_string.push_str(&self.0[self.0.len() - 1].to_string());
    write!(fmt, "{}", formatted_string)
  }
}

impl fmt::Display for SandboxAllow {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    write!(
      fmt,
      "{}",
      match self {
        Self::DownloadsWithoutUserActivation => "allow-downloads-without-user-activation",
        Self::Forms => "allow-forms",
        Self::Modals => "allow-modals",
        Self::OrientationLock => "allow-orientation-lock",
        Self::PointerLock => "allow-pointer-lock",
        Self::Popups => "allow-popups",
        Self::PopupsToEscapeSandbox => "allow-popups-to-escape-sandbox",
        Self::Presentation => "allow-presentation",
        Self::SameOrigin => "allow-same-origin",
        Self::Scripts => "allow-scripts",
        Self::StorageAccessByUserActivation => "allow-storage-access-by-user-activation",
        Self::TopNavigation => "allow-top-navigation",
        Self::TopNavigationByUserActivation => "allow-top-navigation-by-user-activation",
      }
    )
  }
}
