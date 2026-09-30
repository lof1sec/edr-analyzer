# EDR Logs Graph Analyzer

A full-stack web application designed to analyze Endpoint Detection and Response (EDR) logs by parsing CSV exports and mapping the relationships between entities using an interactive graph.

## Features Overview
- **Automated CSV Parsing & Storage:** Upload raw EDR logs, automatically parsed to JSON and stored via PostgreSQL.
- **Interactive Graphing:** Powered by Cytoscape.js, dynamically visualizing process trees, file modifications, and network connections.
- **Dynamic Filtering:** Filter data by global text search, specific event types, usernames, or process IDs.
- **Advanced Graph Layouts:** Seamlessly toggle between Force-directed, Tree, or Node-centric graph layouts.
- **Deep Node Inspection:** Click graph elements to view deep metadata and raw logs in a dedicated side-panel.

## Tech Stack
- **Frontend:** React, Vite, Tailwind CSS v4, Cytoscape.js
- **Backend:** Python, FastAPI, SQLAlchemy
- **Database / Infra:** PostgreSQL 15, Docker & Docker Compose

---

## 🚀 Quickstart & Deployment

### Prerequisites
- Docker & Docker Compose

### Running the Application

1. Open a terminal in the root directory.
2. Run the following command to build and start the containers:

```bash
docker-compose up -d --build
```
*(Note: You may need to run `docker compose up -d --build` on newer Docker versions)*

3. Navigate to **[http://localhost:5173](http://localhost:5173)** in your browser.

---

## 📖 Basic Usage
1. **Upload Logs:** Use the sidebar to upload your raw EDR CSV file.
2. **Analyze Data:** Click a dataset to load its visualization. Use the filters on the right to drill down into specific event types, search terms, or users. Click any node to inspect detailed log data.

To shut down, run `docker-compose down`. Uploaded data persists via Docker volumes.