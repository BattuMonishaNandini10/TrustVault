
from pathlib import Path

app_path = Path("app.py")
source = app_path.read_text(encoding="utf-8")

dashboard_marker = '''    content = """
    <div class="grid stats">STATS</div>'''

if "ADMIN_ACCESS_PANEL" in source or "User Approval & Access Management" in source:
    print("STOP: Admin panel code may already exist. No changes made.")
    raise SystemExit(1)

if dashboard_marker not in source:
    print("STOP: Dashboard insertion point not found. No changes made.")
    raise SystemExit(1)

panel_code = r'''
    access_panel_html = ""

    if role == "admin":
        from markupsafe import escape

        user_rows = ""
        for item in access_users:
            uid = item["id"]
            uname = escape(item["username"])
            user_role = escape(item["role"])
            status = escape(item["account_status"])

            user_rows += f"""
            <tr>
              <td>{uname}</td>
              <td>{user_role}</td>
              <td>{status}</td>
              <td>
                <form method="post"
                      action="/admin/users/{uid}/status"
                      style="display:flex;gap:6px;flex-wrap:wrap">
                  <button class="btn btn-small"
                          name="status" value="approved" type="submit">
                    Approve
                  </button>
                  <button class="btn btn-danger btn-small"
                          name="status" value="rejected" type="submit">
                    Reject
                  </button>
                </form>
              </td>
            </tr>
            """

        if not user_rows:
            user_rows = (
                '<tr><td colspan="4">No users found.</td></tr>'
            )

        doc_rows = ""
        for item in access_docs:
            doc_id = item["id"]
            doc_name = escape(item["filename"])
            doc_owner = escape(item["owner"])

            options = ""
            for user in access_users:
                if user["username"] != item["owner"]:
                    safe_username = escape(user["username"])
                    options += (
                        f'<option value="{safe_username}">'
                        f'{safe_username}</option>'
                    )

            doc_rows += f"""
            <tr>
              <td>{doc_name}</td>
              <td>{doc_owner}</td>
              <td>
                <form method="post" action="/share/{doc_id}"
                      style="display:flex;gap:6px;flex-wrap:wrap">
                  <select name="username" required>
                    <option value="">Choose user</option>
                    {options}
                  </select>
                  <button class="btn btn-small" type="submit">
                    Grant read
                  </button>
                </form>
              </td>
            </tr>
            """

        if not doc_rows:
            doc_rows = (
                '<tr><td colspan="3">No documents found.</td></tr>'
            )

        grant_rows = ""
        for grant in access_grants:
            doc_id = grant["document_id"]
            grant_user = escape(grant["username"])
            grant_name = escape(grant["filename"])

            grant_rows += f"""
            <tr>
              <td>{grant_name}</td>
              <td>{grant_user}</td>
              <td>
                <form method="post"
                      action="/revoke/{doc_id}/{grant_user}">
                  <button class="btn btn-danger btn-small" type="submit">
                    Revoke access
                  </button>
                </form>
              </td>
            </tr>
            """

        if not grant_rows:
            grant_rows = (
                '<tr><td colspan="3">No access grants found.</td></tr>'
            )

        access_panel_html = f"""
        <section class="section" id="admin-access">
          <div class="section-head">
            <div>
              <h2>User Approval &amp; Access Management</h2>
              <p class="muted small">
                Approve accounts, grant document access, and revoke access.
              </p>
            </div>
          </div>

          <h3>Manage users</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>USERNAME</th><th>ROLE</th>
                  <th>STATUS</th><th>ACTION</th>
                </tr>
              </thead>
              <tbody>{user_rows}</tbody>
            </table>
          </div>

          <h3 style="margin-top:24px">Grant document access</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DOCUMENT</th><th>OWNER</th>
                  <th>GRANT READ ACCESS</th>
                </tr>
              </thead>
              <tbody>{doc_rows}</tbody>
            </table>
          </div>

          <h3 style="margin-top:24px">Existing access grants</h3>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>DOCUMENT</th><th>USER</th><th>ACTION</th>
                </tr>
              </thead>
              <tbody>{grant_rows}</tbody>
            </table>
          </div>
        </section>
        """

'''

source = source.replace(
    dashboard_marker,
    panel_code + dashboard_marker,
    1
)

quick_actions_end = '''      <div class="grid quick-grid">ACTIONS</div>
    </section>

    <section class="section">'''

if quick_actions_end not in source:
    print("STOP: Quick Actions insertion point not found.")
    raise SystemExit(1)

source = source.replace(
    quick_actions_end,
    '''      <div class="grid quick-grid">ACTIONS</div>
    </section>

    ADMIN_ACCESS_PANEL

    <section class="section">''',
    1
)

replace_marker = '''    ).replace("ROWS", rows).replace(
        "MYDOCS", url_for('''

if replace_marker not in source:
    print("STOP: Dashboard replacement chain not found.")
    raise SystemExit(1)

source = source.replace(
    replace_marker,
    '''    ).replace(
        "ADMIN_ACCESS_PANEL", access_panel_html
    ).replace("ROWS", rows).replace(
        "MYDOCS", url_for(''',
    1
)

compile(source, str(app_path), "exec")
app_path.write_text(source, encoding="utf-8")
print("SUCCESS: Admin dashboard panel inserted.")
print("Next: run python -m py_compile app.py")
