import json
from pathlib import Path

from fastapi import APIRouter, HTTPException


router = APIRouter(
    prefix="/api/tickets",
    tags=["Tickets"]
)


ROOT_DIR = Path(__file__).resolve().parents[3]

TICKET_DIR = ROOT_DIR / "tickets"


@router.get("")
async def get_tickets():

    if not TICKET_DIR.exists():
        return []

    tickets = []

    for ticket_file in TICKET_DIR.glob(
        "SOC-*.json"
    ):

        try:

            ticket = json.loads(
                ticket_file.read_text(
                    encoding="utf-8"
                )
            )

            tickets.append(
                ticket
            )

        except json.JSONDecodeError:
            continue

    tickets.sort(
        key=lambda item: item.get(
            "created_at",
            ""
        ),
        reverse=True
    )

    return tickets


@router.get("/{ticket_id}")
async def get_ticket(
    ticket_id: str
):

    ticket_path = (
        TICKET_DIR
        / f"{ticket_id}.json"
    )

    if not ticket_path.exists():

        raise HTTPException(
            status_code=404,
            detail="Ticket not found"
        )

    return json.loads(
        ticket_path.read_text(
            encoding="utf-8"
        )
    )