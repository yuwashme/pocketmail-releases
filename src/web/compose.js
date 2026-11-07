// Upgrade the plain form only once the editor is ready.
(() => {
  const editor = document.querySelector('#editor');
  const body = document.querySelector('#body');
  const html = document.querySelector('#html');
  const status = document.querySelector('#compose-status');
  const tags = new Set('p div span br hr strong b em i u s del sub sup blockquote pre code ul ol li h1 h2 h3 h4 h5 h6 a table thead tbody tfoot tr td th'.split(' '));
  const skip = new Set('script style link meta head iframe object embed form input button textarea select svg math img video audio template'.split(' '));
  const styles = 'color background-color font-family font-size font-weight font-style text-decoration-line text-align line-height white-space vertical-align border-color border-width border-style border-collapse padding'.split(' ');

  // Parse in an inert template. Only newly created, allowlisted nodes enter the editor.
  function formatted(markup) {
    const source = document.createElement('template');
    source.innerHTML = markup;
    const result = document.createElement('div');
    function copy(node, parent) {
      if (node.nodeType === Node.TEXT_NODE) { parent.append(node.data); return; }
      if (node.nodeType !== Node.ELEMENT_NODE || skip.has(node.localName)) return;
      let dest = parent;
      if (tags.has(node.localName) || node.localName === 'font') {
        dest = document.createElement(node.localName === 'font' ? 'span' : node.localName);
        if (node.localName === 'font') {
          dest.style.color = node.getAttribute('color') || '';
          dest.style.fontFamily = node.getAttribute('face') || '';
        }
        if (node.localName === 'a') {
          try {
            const url = new URL(node.getAttribute('href'));
            if (['https:', 'http:', 'mailto:'].includes(url.protocol)) dest.href = url.href;
          } catch { /* Discard relative and malformed links. */ }
        }
        for (const attr of ['colspan', 'rowspan', 'start']) {
          const val = node.getAttribute(attr);
          if (val && /^\d{1,3}$/.test(val)) dest.setAttribute(attr, val);
        }
        for (const key of styles) {
          const value = node.style?.getPropertyValue(key);
          if (value) dest.style.setProperty(key, value);
        }
        parent.append(dest);
      }
      for (const child of node.childNodes) copy(child, dest);
    }
    for (const node of source.content.childNodes) copy(node, result);
    return result.innerHTML;
  }

  let bookmark;
  document.addEventListener('selectionchange', () => {
    const sel = getSelection();
    if (sel.rangeCount && editor.contains(sel.getRangeAt(0).commonAncestorContainer))
      bookmark = sel.getRangeAt(0).cloneRange();
  });
  function focusEditor() {
    const range = bookmark?.cloneRange() || document.createRange();
    if (!editor.contains(range.commonAncestorContainer)) {
      range.selectNodeContents(editor);
      range.collapse(false);
    }
    editor.focus();
    const sel = getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
  }
  function insert(markup, plain) {
    const safe = markup && formatted(markup);
    if (safe || plain) {
      document.execCommand(safe ? 'insertHTML' : 'insertText', false, safe || plain);
      status.textContent = '';
    } else status.textContent = 'No message text found on the clipboard.';
  }
  editor.addEventListener('paste', event => {
    event.preventDefault();
    insert(event.clipboardData.getData('text/html'), event.clipboardData.getData('text/plain'));
  });
  editor.addEventListener('drop', event => event.preventDefault());
  for (const button of document.querySelectorAll('[data-command]')) {
    button.addEventListener('mousedown', event => event.preventDefault());
    button.addEventListener('click', () => {
      focusEditor();
      document.execCommand(button.dataset.command);
    });
  }
  document.querySelector('#paste-message').addEventListener('click', async () => {
    try {
      let markup = '', plain = '';
      if (navigator.clipboard.read) {
        for (const item of await navigator.clipboard.read()) {
          if (!markup && item.types.includes('text/html')) markup = await (await item.getType('text/html')).text();
          if (!plain && item.types.includes('text/plain')) plain = await (await item.getType('text/plain')).text();
        }
      } else {
        throw new Error('Native paste needed');
      }
      focusEditor();
      insert(markup, plain);
    } catch {
      focusEditor();
      status.textContent = 'Press ⌘V or Ctrl+V to paste with formatting.';
    }
  });
  body.form.addEventListener('submit', event => {
    body.value = editor.innerText;
    html.value = editor.innerHTML;
    const size = new URLSearchParams(new FormData(body.form)).toString().length;
    if (!body.value.trim() || size > 262144) {
      event.preventDefault();
      status.textContent = body.value.trim() ? 'This message is too large. Shorten it before sending.' : 'Enter a message before sending.';
      editor.focus();
    }
  });
  editor.innerText = body.value;
  body.required = false;
  body.hidden = true;
  document.querySelector('#rich-compose').hidden = false;
  document.querySelector('#body-label').addEventListener('click', () => editor.focus());
})();
