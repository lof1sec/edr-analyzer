# EDR Logs Graph Analyzer

A full-stack web application designed to analyze Endpoint Detection and Response (EDR) logs (e.g., Microsoft Defender) by parsing CSV exports and mapping the relationships between entities using an interactive graph.

## Features

- **Automated Parsing:** Upload raw EDR CSV files. The backend automatically parses the rows into JSON and stores them in a scalable PostgreSQL database.
- **Interactive Graph Visualization:** Powered by **Cytoscape.js**, easily view process execution trees, file modifications, network connections, and more.
- **Advanced Filtering:** Built-in sidebar to dynamically filter the graph by:
  - Global Text Search
  - Event Types (e.g., `ProcessCreated`, `NetworkConnectionEvents`)
  - Usernames
- **Detailed Node Inspection:** Click on any node (Process, File, Registry, Network, Alert) to view the raw log details and observed actions in a dedicated detail panel.
- **Dark/Light Mode:** First-class support for both themes to ensure comfortable analysis in any environment.
- **Scalable Architecture:** Uses PostgreSQL `JSONB` columns to flexibly adapt to future log formats (like CrowdStrike Falcon).

## Tech Stack

- **Frontend:** React, Vite, Tailwind CSS v4, Cytoscape.js (`react-cytoscapejs`), Lucide React.
- **Backend:** Python, FastAPI, SQLAlchemy, Uvicorn.
- **Database:** PostgreSQL 15.
- **Orchestration:** Docker & Docker Compose.

---

## 🚀 Quickstart & Deployment

The application is containerized and managed via Docker Compose, making it incredibly easy to run locally.

### Prerequisites
- [Docker](https://docs.docker.com/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Running the Application

1. Clone or download this repository.
2. Open a terminal in the root directory (where `docker-compose.yml` is located).
3. Run the following command to build and start the containers:

```bash
docker-compose up -d --build
```
*(Note: If you have a newer version of docker, you may need to run `docker compose up -d --build`)*

4. Wait a few moments for the database to initialize and the servers to start.
5. Open your web browser and navigate to:
   **[http://localhost:5173](http://localhost:5173)**

---

## 📖 How to Use

### 1. Uploading Logs
- On the left sidebar, click the **"Click to upload CSV"** area.
- Select your raw EDR log export (e.g., `Defender.csv`).
- The backend will parse the file, convert the records to JSON, and store them in the database.
- Once finished, the new dataset will appear in the "Datasets" list.

### 2. Viewing the Graph
- Click on your newly uploaded dataset in the sidebar to load it.
- The graph will render in the main view area.
  - **Red Rounded Boxes:** Processes
  - **Blue Rectangles:** Files
  - **Purple Hexagons:** Modules / DLLs
  - **Teal Rectangles:** Network Connections
  - **Brown Rectangles:** Registry Keys
  - **Yellow Rectangles:** Command Lines
  - **Red Stars:** Antivirus Alerts

### 3. Filtering the Data
- Use the **Filters & Search** panel on the right side of the screen.
- **Global Search:** Type any string (e.g., `powershell`, `192.168.1.5`) to isolate nodes containing that text. You can separate multiple terms with a comma.
- **Event Types:** Uncheck specific event types to hide edges and their associated artifacts from the graph.
- **Users:** Isolate activity down to specific user accounts.

### 4. Inspecting Details
- Click on any node in the graph.
- A popup panel will appear in the bottom-left corner containing the raw metadata associated with that node, including Command Lines, Hashes, and Process Details.

---

## Stopping the Application

To shut down the application and database, run:
```bash
docker-compose down
```
*Note: Your uploaded datasets and parsed logs are stored in a Docker volume (`postgres_data`) and will persist between restarts.*
