use std::fmt;

#[derive(Debug, Clone)]
pub struct TrustedTypes<'a> {
  inner: Vec<&'a str>,
}

impl<'a> TrustedTypes<'a> {
  pub fn new_with(trusted_type: &'a str) -> Self {
    TrustedTypes {
      inner: vec![trusted_type],
    }
  }

  pub fn add_borrowed<'b>(&'b mut self, trusted_type: &'a str) -> &'b mut Self {
    self.inner.push(trusted_type);
    self
  }

  pub fn add(mut self, trusted_type: &'a str) -> Self {
    self.inner.push(trusted_type);
    self
  }

  pub fn get(&self) -> &Vec<&'a str> {
    &self.inner
  }
}

impl<'a> fmt::Display for TrustedTypes<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.inner.len() < 1 {
      return Err(fmt::Error);
    }
    let mut formatted_string = String::new();

    for trusted_type in &self.inner[0..self.inner.len() - 1] {
      formatted_string.push_str(trusted_type);
      formatted_string.push_str(" ");
    }

    formatted_string.push_str(&self.inner[self.inner.len() - 1]);
    write!(fmt, "{}", formatted_string)
  }
}
