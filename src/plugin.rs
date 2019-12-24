use std::fmt;

#[derive(Debug, Clone)]
/// Used for `PluginTypes` [`Directive`].
///
/// # Example usage
/// ```rust
/// let flash = csp::Plugins::new().add(("application", "x-shockwave-flash"));
/// ```
///  to get `application/x-shockwave-flash`
///
/// [`Directive`]: Directive
pub struct Plugins<'a> {
  inner: Vec<(&'a str, &'a str)>,
}

impl<'a> Plugins<'a> {
  pub fn new_with(plugin: (&'a str, &'a str)) -> Self {
    Plugins {
      inner: vec![plugin],
    }
  }

  pub fn add_borrowed<'b>(&'b mut self, plugin: (&'a str, &'a str)) -> &'b mut Self {
    self.inner.push(plugin);
    self
  }

  pub fn add(mut self, plugin: (&'a str, &'a str)) -> Self {
    self.inner.push(plugin);
    self
  }

  pub fn get(&self) -> &Vec<(&'a str, &'a str)> {
    &self.inner
  }
}

impl<'a> fmt::Display for Plugins<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.inner.len() < 1 {
      return Err(fmt::Error);
    }
    let mut formatted_string = String::new();

    for plugin in &self.inner[0..self.inner.len() - 1] {
      formatted_string.push_str(&format!("{}/{}", plugin.0, plugin.1));
      formatted_string.push_str(" ");
    }

    let last = &self.inner[self.inner.len() - 1];

    formatted_string.push_str(&format!("{}/{}", last.0, last.1));
    write!(fmt, "{}", formatted_string)
  }
}
