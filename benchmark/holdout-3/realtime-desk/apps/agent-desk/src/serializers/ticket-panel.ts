interface TicketRow {
  id: string;
  subject: string;
  status: string;
  priority: string;
  assignee_id: string | null;
  updated_at: Date;
  requester_email: string;
  requester_name: string;
}

interface TimelineRow {
  id: string;
  kind: string;
  body: string;
  author_id: string | null;
  created_at: Date;
}

/** The exact shape the detail panel binds to. Nothing else is sent. */
export function ticketPanel(ticket: TicketRow, timeline: TimelineRow[]) {
  return {
    id: ticket.id,
    subject: ticket.subject,
    status: ticket.status,
    priority: ticket.priority,
    assigneeId: ticket.assignee_id,
    updatedAt: ticket.updated_at,
    requester: { email: ticket.requester_email, name: ticket.requester_name },
    timeline: timeline.map((event) => ({
      id: event.id,
      kind: event.kind,
      body: event.body,
      authorId: event.author_id,
      createdAt: event.created_at
    }))
  };
}
