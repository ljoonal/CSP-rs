use std::fmt;

#[derive(Debug, Clone)]
pub struct ReportUris<'a> {
  inner: Vec<&'a str>,
}

impl<'a> ReportUris<'a> {
  pub fn new_with(uri: &'a str) -> Self {
    ReportUris { inner: vec![uri] }
  }

  pub fn add_borrowed<'b>(&'b mut self, uri: &'a str) -> &'b mut Self {
    self.inner.push(uri);
    self
  }

  pub fn add(mut self, uri: &'a str) -> Self {
    self.inner.push(uri);
    self
  }

  pub fn get(&self) -> &Vec<&'a str> {
    &self.inner
  }
}

impl<'a> fmt::Display for ReportUris<'a> {
  fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
    if self.inner.len() < 1 {
      return Err(fmt::Error);
    }
    let mut formatted_string = String::new();

    for uri in &self.inner[0..self.inner.len() - 1] {
      formatted_string.push_str(uri);
      formatted_string.push_str(" ");
    }

    formatted_string.push_str(&self.inner[self.inner.len() - 1]);
    write!(fmt, "{}", formatted_string)
  }
}
