# AI SOC MCP

AI-assisted Security Operations Center proof of concept. The project streams mock or Windows security events, correlates detections into incidents, investigates incidents through Azure OpenAI and MCP tools, creates tickets, exposes a FastAPI API, and provides a minimal Streamlit dashboard.

## Components

- **MCP server**: security evidence and ticket tools on port `8000`
- **FastAPI server**: monitoring pipeline and REST/WebSocket API on port `8001`
- **Streamlit UI**: lightweight dashboard on port `8501`
- **Providers**: mock data by default; Windows event, identity, endpoint, and log providers are available

## Requirements

- Windows 10 or 11
- Python 3.10 or newer
- Azure OpenAI resource and deployment
- PowerShell

Windows live-data mode may require an elevated terminal to read Security event logs. Mock mode does not require elevation.

## Setup

Run all commands from the project root:

```powershell
cd "D:\SOC POC\cybersecurity_soc_mcp"
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

If PowerShell blocks virtual environment activation, allow local scripts for the current user, then retry activation:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

## Configuration

Create `.env` in the project root:

```dotenv
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
AZURE_OPENAI_API_VERSION=2024-10-21
AZURE_OPENAI_DEPLOYMENT=your-deployment-name

MCP_URL=http://127.0.0.1:8000/mcp

EVENT_SOURCE=mock
IDENTITY_SOURCE=mock
ENDPOINT_SOURCE=mock
LOG_SOURCE=mock
```

Azure values are required when starting the FastAPI application because its monitor loads the investigation agent at startup. Keep secrets out of source control.

## Start Full Application

Use three PowerShell terminals. Activate the virtual environment in each terminal.

### 1. Start MCP Server

```powershell
cd "D:\SOC POC\cybersecurity_soc_mcp"
.\.venv\Scripts\Activate.ps1
python -m app.mcp_server.server
```

MCP endpoint: `http://127.0.0.1:8000/mcp`

### 2. Start FastAPI and Monitor

```powershell
cd "D:\SOC POC\cybersecurity_soc_mcp"
.\.venv\Scripts\Activate.ps1
python -m uvicorn app.api.server:app --host 127.0.0.1 --port 8001 --reload
```

Useful URLs:

- API health: `http://127.0.0.1:8001/api/health`
- OpenAPI docs: `http://127.0.0.1:8001/docs`
- WebSocket: `ws://127.0.0.1:8001/ws`

### 3. Start Streamlit UI

```powershell
cd "D:\SOC POC\cybersecurity_soc_mcp"
.\.venv\Scripts\Activate.ps1
$env:SOC_API_URL = "http://127.0.0.1:8001"
python -m streamlit run streamlit_app.py --server.port 8501
```

Dashboard: `http://localhost:8501`

Stop any service with `Ctrl+C` in its terminal.

## Windows Live-Data Mode

Change supported providers in `.env`:

```dotenv
EVENT_SOURCE=windows
IDENTITY_SOURCE=windows
ENDPOINT_SOURCE=windows
LOG_SOURCE=windows
```

Restart MCP and FastAPI after changing `.env`. Run terminals as Administrator if Windows denies access to Security event logs.

To return to bundled demo data, set all four values back to `mock`.

## Run Tests

```powershell
cd "D:\SOC POC\cybersecurity_soc_mcp"
.\.venv\Scripts\Activate.ps1
python -m pytest -q
```

Run one test file:

```powershell
python -m pytest tests\test_risk_engine.py -q
```

## API Routes

- `GET /api/health` - API and monitor status
- `GET /api/system/summary` - incident and ticket counts
- `GET /api/providers/status` - selected data providers
- `GET /api/incidents` - all incidents
- `GET /api/incidents/{incident_id}` - incident details
- `GET /api/tickets` - all tickets
- `GET /api/tickets/{ticket_id}` - ticket details
- `GET /api/audit` - audit history
- `WS /ws` - live monitoring events

## Optional Monitor-Only Run

`main.py` starts the monitor without FastAPI or Streamlit. Start the MCP server first, then run:

```powershell
python main.py
```

Do not run `main.py` and the FastAPI server together unless duplicate monitoring is intentional.

## Generated Data

- Incidents: `incidents/INC-*.json`
- Tickets: `tickets/SOC-*.json`
- Audit log: `audit_logs/soc_audit.jsonl`
- Mock input events: `app/live_data/events.json`

## Troubleshooting

### `Missing environment variables`

Confirm `.env` exists in the project root and contains all four `AZURE_OPENAI_*` values.

### `Cannot reach API`

Confirm FastAPI is running on port `8001`. In the Streamlit sidebar, set API URL to `http://127.0.0.1:8001`.

### MCP connection failure

Start the MCP server before FastAPI and confirm `MCP_URL=http://127.0.0.1:8000/mcp`.

### Port already in use

MCP is fixed to port `8000`. Keep FastAPI on `8001`, or stop the process already using the required port:

```powershell
Get-NetTCPConnection -LocalPort 8000,8001,8501 -ErrorAction SilentlyContinue |
    Select-Object LocalPort, State, OwningProcess
```