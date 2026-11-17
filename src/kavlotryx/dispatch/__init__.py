"""Ticket dispatch (FR-DS) and ticket trackers."""

from __future__ import annotations

from kavlotryx.config import Settings
from kavlotryx.dispatch.base import Ticket, TicketTracker, TrackerError
from kavlotryx.dispatch.fake import FakeTracker
from kavlotryx.dispatch.jira import JiraCloudTracker


def make_tracker(settings: Settings) -> TicketTracker:
    if settings.tracker == "jira":
        if not (settings.jira_url and settings.jira_email and settings.jira_token):
            raise TrackerError("KAVLO_JIRA_URL, KAVLO_JIRA_EMAIL and KAVLO_JIRA_TOKEN must be set")
        return JiraCloudTracker(settings.jira_url, settings.jira_email, settings.jira_token,
                                issue_type=settings.jira_issue_type)
    if settings.tracker == "fake":
        return FakeTracker(settings.fake_tracker_file)
    raise TrackerError(f"unknown tracker {settings.tracker!r}; use 'jira' or 'fake'")


__all__ = ["FakeTracker", "JiraCloudTracker", "Ticket", "TicketTracker", "TrackerError", "make_tracker"]
