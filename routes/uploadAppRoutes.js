const express = require("express");
const router = express.Router();

// GET uploaded apps list
router.get("/apps", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const result = await esClient.search({
      index: "apps",
      size: 100,
      query: { term: { uploadedByUser: true } }, // Boolean exact match
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => hit._source);

    let html = `
      <html>
      <head>
        <title>Uploaded Apps</title>
        <style>
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ddd; padding: 8px; }
          th { background-color: #f2f2f2; }
          button { padding: 6px 12px; cursor: pointer; }
        </style>
      </head>
      <body>
        <h1>Uploaded Apps</h1>
        <table>
          <thead>
            <tr>
              <th>App Name</th>
              <th>Package Name</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
    `;

    apps.forEach((app) => {
      html += `
        <tr>
          <td>${app.appName || ""}</td>
          <td>${app.packageName}</td>
          <td>${app.status || "unknown"}</td>
          <td>
            <form method="POST" action="/uploadapp/apps/${app.sha256}/upload-sandbox" style="margin:0;">
              <button type="submit">Upload to Sandbox</button>
            </form>
          </td>
        </tr>
      `;
    });

    html += `
          </tbody>
        </table>
      </body>
      </html>
    `;

    res.send(html);
  } catch (err) {
    console.error("Failed to fetch apps for upload app page:", err);
    res.status(500).send("Error loading apps");
  }
});

// POST upload to sandbox
router.post("/apps/:sha256/upload-sandbox", async (req, res) => {
  const sha256 = req.params.sha256;
  const esClient = req.app.get("esClient");

  try {
    const searchRes = await esClient.search({
      index: "apps",
      size: 1,
      query: { term: { sha256: { value: sha256 } } },
    });

    if (searchRes.hits.hits.length === 0) {
      return res.status(404).send("App not found");
    }

    const docId = searchRes.hits.hits[0]._id;

    // Your MobSF sandbox upload logic here...

    // Update exactly like your curl command
    await esClient.update({
      index: "apps",
      id: docId,
      body: {
        doc: {
          status: "sandbox_submitted",
          uploadedByUser: true, // ensure it's marked as uploaded by user
          timestamp: new Date(),
        },
      },
    });

    console.log(`✅ Marked app ${sha256} as uploadedByUser = true`);
    res.redirect("/uploadapp/apps");
  } catch (err) {
    console.error(`Failed to submit app ${sha256} to sandbox:`, err);
    res.status(500).send("Failed to submit to sandbox");
  }
});

module.exports = router;