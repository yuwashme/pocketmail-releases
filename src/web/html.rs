//! Pages built so that only markup written in the source reaches the browser unescaped: `raw`
//! takes `&'static str` literals, everything else goes through `text`.

use super::CSS_PATH;

pub const SITE: &str = "Pocketmail";

#[derive(Default)]
pub struct Html(String);

impl Html {
    pub fn raw(&mut self, markup: &'static str) -> &mut Html {
        self.0.push_str(markup);
        self
    }

    /// Text for an element or a double-quoted attribute value, escaped.
    pub fn text(&mut self, s: &str) -> &mut Html {
        for c in s.chars() {
            match c {
                '&' => self.0.push_str("&amp;"),
                '<' => self.0.push_str("&lt;"),
                '>' => self.0.push_str("&gt;"),
                '"' => self.0.push_str("&quot;"),
                '\'' => self.0.push_str("&#39;"),
                c => self.0.push(c),
            }
        }
        self
    }

    /// A labelled input; with an error, the message sits between the label and the input and
    /// the input points to it. Text inputs (user names and addresses) are not capitalized or
    /// spellchecked.
    pub fn field(&mut self, f: &Field<'_>) -> &mut Html {
        self.raw("<label for=\"").raw(f.name).raw("\">").raw(f.label).raw("</label>");
        if let Some(error) = f.error {
            self.raw("<p id=\"").raw(f.name).raw("-error\" class=\"error\">").text(error).raw("</p>");
        }
        self.raw("<input id=\"").raw(f.name).raw("\" name=\"").raw(f.name).raw("\" type=\"").raw(f.kind);
        self.raw("\" autocomplete=\"").raw(f.autocomplete).raw("\"");
        if f.kind == "text" {
            self.raw(" autocapitalize=\"none\" spellcheck=\"false\"");
        }
        if let Some(value) = f.value {
            self.raw(" value=\"").text(value).raw("\"");
        }
        if f.error.is_some() {
            self.raw(" aria-invalid=\"true\" aria-describedby=\"").raw(f.name).raw("-error\"");
        }
        self.raw(">")
    }

    /// An address; a catch-all with its meaning in plain words.
    pub fn address(&mut self, address: &str) -> &mut Html {
        self.text(address);
        if let Some(domain) = address.strip_prefix('@') {
            self.raw(" (all other mail for ").text(domain).raw(")");
        }
        self
    }

    /// The hidden CSRF field of a form.
    pub fn csrf(&mut self, token: &str) -> &mut Html {
        self.raw("<input type=\"hidden\" name=\"csrf\" value=\"").text(token).raw("\">")
    }

    /// The whole document: `title` as the heading, a Sign out button when `csrf` is given (a
    /// signed-in page), then `body`. `nav`, for an admin, is this page's path: the header gets the
    /// admin links, the one to this page marked current.
    pub fn page(title: &'static str, csrf: Option<&str>, nav: Option<&str>, body: impl FnOnce(&mut Html)) -> Vec<u8> {
        let mut h = Html(String::with_capacity(2048));
        h.raw("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">");
        h.raw("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        h.raw("<title>").raw(title).raw(" - ").raw(SITE).raw("</title>");
        h.raw("<link rel=\"stylesheet\" href=\"").raw(CSS_PATH).raw("\"></head>\n<body><header><p>").raw(SITE).raw("</p>");
        if let Some(current) = nav {
            h.raw("<nav aria-label=\"Settings\"><ul>");
            for (href, text) in [("/accounts", "Accounts"), ("/me", "Your account")] {
                h.raw("<li><a href=\"").raw(href).raw("\"");
                if href == current {
                    h.raw(" aria-current=\"page\"");
                }
                h.raw(">").raw(text).raw("</a></li>");
            }
            h.raw("</ul></nav>");
        }
        if let Some(token) = csrf {
            h.raw("<form method=\"post\" action=\"/logout\">").csrf(token);
            h.raw("<button type=\"submit\" class=\"secondary\">Sign out</button></form>");
        }
        h.raw("</header>\n<main><h1>").raw(title).raw("</h1>\n");
        body(&mut h);
        h.raw("</main></body></html>\n");
        h.0.into_bytes()
    }
}

pub struct Field<'a> {
    /// Also the id.
    pub name: &'static str,
    pub label: &'static str,
    pub kind: &'static str,
    pub autocomplete: &'static str,
    /// Never given for a password.
    pub value: Option<&'a str>,
    pub error: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_escaped_markup_is_not() {
        let mut h = Html::default();
        h.raw("<b>").text("<script>\"x&'y\"</script>").raw("</b>");
        assert_eq!(h.0, "<b>&lt;script&gt;&quot;x&amp;&#39;y&quot;&lt;/script&gt;</b>");
    }

    #[test]
    fn field_with_error_points_to_it() {
        let mut h = Html::default();
        let f = Field { name: "login", label: "User name", kind: "text", autocomplete: "username", value: Some("a\"b"), error: Some("Wrong.") };
        h.field(&f);
        assert_eq!(
            h.0,
            "<label for=\"login\">User name</label><p id=\"login-error\" class=\"error\">Wrong.</p>\
             <input id=\"login\" name=\"login\" type=\"text\" autocomplete=\"username\" autocapitalize=\"none\" spellcheck=\"false\" value=\"a&quot;b\" \
             aria-invalid=\"true\" aria-describedby=\"login-error\">"
        );
    }
}
