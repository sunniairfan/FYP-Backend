const express = require("express");
const router = express.Router();

// GET uploaded apps list
router.get("/apps", async (req, res) => {
  const esClient = req.app.get("esClient");
  try {
    const result = await esClient.search({
      index: "apps",
      size: 100,
      query: { term: { uploadedByUser: true } },
      sort: [{ timestamp: { order: "desc" } }],
    });

    const apps = result.hits.hits.map((hit) => hit._source);

    let html = `
      <html>
      <head>
        <title>Uploaded Apps</title>
        <style>
          body {
            background-color: #0d1b2a;
            color: white;
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
          }
          h1 {
            text-align: center;
            margin-bottom: 20px;
            font-size: 2rem;
            color: #ffffff;
          }
          table {
            width: 100%;
            border-spacing: 0;
            border-collapse: separate;
            border-radius: 12px;
            overflow: hidden;
            background-color: #1b263b;
            box-shadow: 0 4px 20px rgba(0,0,0,0.4);
          }
          thead {
            background-color: #415a77;
          }
          th {
            padding: 15px;
            text-align: left;
            font-size: 1rem;
            font-weight: bold;
            color: white;
          }
          td {
            padding: 15px;
            border-bottom: 1px solid #415a77;
          }
          tr:hover {
            background-color: #273b54;
          }
          .status {
            font-weight: bold;
            padding: 6px 10px;
            border-radius: 5px;
            display: inline-block;
          }
          .status.unknown {
            background-color: #ffb703;
            color: #1b263b;
          }
          .status.safe {
            background-color: #90ee90;
            color: #1b263b;
          }
          .status.malicious {
            background-color: #ff4d4d;
            color: white;
          }
          button {
            padding: 10px 16px;
            background-color: #0077b6;
            border: none;
            border-radius: 6px;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: background-color 0.3s ease, transform 0.2s ease;
          }
          button:hover {
            background-color: #0096c7;
            transform: scale(1.05);
          }
          form {
            margin: 0;
          }
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
          <td>
            <span class="status ${app.status || "unknown"}">
              ${app.status || "unknown"}
            </span>
          </td>
          <td>
            <form method="POST" action="/uploadapp/apps/${app.sha256}/upload-sandbox">
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

    await esClient.update({
      index: "apps",
      id: docId,
      body: {
        doc: {
          status: "sandbox_submitted",
          uploadedByUser: true,
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
