import asyncio
import logging
import time
from uuid import uuid4

from starlette.datastructures import Headers
from starlette.requests import Request

from open_webui.models.schedules import Schedules
from open_webui.models.models import Models
from open_webui.models.users import Users
from open_webui.utils.middleware import process_chat_payload
from open_webui.utils.schedule_utils import execute_with_tools
from open_webui.config import SCHEDULE_RUN_RETENTION_DAYS
from open_webui.env import SRC_LOG_LEVELS

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])

SCHEDULE_CHECK_INTERVAL = 60  # Check every 60 seconds


def _create_mock_request(app):
    """Create a mock Request object for internal use."""
    return Request(
        {
            "type": "http",
            "asgi.version": "3.0",
            "asgi.spec_version": "2.0",
            "method": "POST",
            "path": "/internal/schedule",
            "query_string": b"",
            "headers": Headers({}).raw,
            "client": ("127.0.0.1", 12345),
            "server": ("127.0.0.1", 80),
            "scheme": "http",
            "app": app,
        }
    )


async def _execute_schedule(app, schedule):
    """Execute a single schedule by calling generate_chat_completion."""
    run_id = str(uuid4())
    run = Schedules.insert_new_run(run_id, schedule.id)

    if not run:
        log.error(f"Failed to create run record for schedule '{schedule.name}'")
        return

    Schedules.update_run_by_id(
        run_id,
        {"status": "running", "started_at": int(time.time())},
    )

    try:
        user = Users.get_user_by_id(schedule.user_id)
        if not user:
            raise ValueError(f"Schedule owner user '{schedule.user_id}' not found")

        models = app.state.MODELS
        model_id = schedule.model_id

        if model_id not in models:
            raise ValueError(f"Model '{model_id}' not found")

        model = models[model_id]
        request = _create_mock_request(app)

        # Build features dict from capabilities stored in meta
        meta = schedule.meta or {}
        capabilities = meta.get("capabilities", {})
        features = {}
        for key in ["web_search", "code_interpreter", "image_generation"]:
            if capabilities.get(key):
                features[key] = True

        tool_ids = schedule.tools if schedule.tools else []

        # Determine function_calling mode from model info (same as main.py chat_completion)
        model_info = Models.get_model_by_id(model_id)
        model_info_params = (
            model_info.params.model_dump()
            if model_info and model_info.params
            else {}
        )
        function_calling = (
            "native"
            if model_info_params.get("function_calling") == "native"
            else "default"
        )

        now_str = time.strftime("%Y-%m-%d %H:%M:%S %Z")
        system_content = (
            f"You are executing a scheduled task. "
            f"Current date and time: {now_str}. "
            f"Respond thoroughly and completely to the user's request."
        )

        payload = {
            "model": model_id,
            "messages": [
                {"role": "system", "content": system_content},
                {"role": "user", "content": schedule.prompt},
            ],
            "stream": False,
            "tool_ids": tool_ids,
            "features": features,
        }

        metadata = {
            "tool_ids": tool_ids,
            "features": features,
            "task": "schedule_run",
            "schedule_id": schedule.id,
            "params": {
                "function_calling": function_calling,
            },
        }

        # Process through middleware pipeline (resolves tools, features)
        payload, metadata, events = await process_chat_payload(
            request, payload, user, metadata, model
        )

        # Execute with tool-calling loop (handles tool_calls → execute → re-call)
        ai_content = await execute_with_tools(request, payload, metadata, user)

        # Build tools display: user tools + enabled capabilities
        all_tools_display = list(tool_ids)
        for key in ["web_search", "code_interpreter", "image_generation"]:
            if capabilities.get(key):
                all_tools_display.append(key)
        if capabilities.get("builtin_tools"):
            all_tools_display.append("builtin_tools")
        tools_text = ", ".join(all_tools_display) if all_tools_display else "None"

        result_text = (
            f"## Schedule: {schedule.name}\n\n"
            f"**Model:** {schedule.model_id}\n"
            f"**Task:** {schedule.prompt}\n"
            f"**Tools:** {tools_text}\n\n"
            f"---\n\n"
            f"## AI Response\n\n"
            f"{ai_content}\n\n"
            f"---\n\n"
            f"*Completed at {time.strftime('%Y-%m-%d %H:%M:%S')}*"
        )

        Schedules.update_run_by_id(
            run_id,
            {
                "status": "completed",
                "result": result_text,
                "completed_at": int(time.time()),
            },
        )

        log.info(f"Schedule '{schedule.name}' executed successfully (run {run_id})")

    except Exception as e:
        log.exception(f"Error executing schedule '{schedule.name}': {e}")
        error_text = (
            f"## Schedule: {schedule.name}\n\n"
            f"**Model:** {schedule.model_id}\n"
            f"**Task:** {schedule.prompt}\n\n"
            f"---\n\n"
            f"## Error\n\n"
            f"Failed to execute: {str(e)}\n\n"
            f"---\n\n"
            f"*Failed at {time.strftime('%Y-%m-%d %H:%M:%S')}*"
        )
        Schedules.update_run_by_id(
            run_id,
            {
                "status": "failed",
                "result": error_text,
                "completed_at": int(time.time()),
            },
        )

    # Advance schedule to next run time (or deactivate if 'once')
    Schedules.advance_schedule(schedule.id)


async def periodic_schedule_check(app):
    """Background task that periodically checks for and executes due schedules."""
    log.info("Schedule executor started")

    # Wait a bit for the app to fully initialize (models loaded, etc.)
    await asyncio.sleep(30)

    while True:
        try:
            now = int(time.time())

            # Clean up old runs based on retention policy
            if SCHEDULE_RUN_RETENTION_DAYS > 0:
                cutoff = now - (SCHEDULE_RUN_RETENTION_DAYS * 86400)
                deleted = Schedules.delete_runs_older_than(cutoff)
                if deleted > 0:
                    log.info(
                        f"Cleaned up {deleted} schedule run(s) older than {SCHEDULE_RUN_RETENTION_DAYS} days"
                    )

            due_schedules = Schedules.get_due_schedules(now)

            if due_schedules:
                log.info(f"Found {len(due_schedules)} due schedule(s) to execute")

            for schedule in due_schedules:
                try:
                    await _execute_schedule(app, schedule)
                except Exception as e:
                    log.exception(
                        f"Unhandled error executing schedule '{schedule.name}': {e}"
                    )

        except Exception as e:
            log.exception(f"Error in schedule check loop: {e}")

        await asyncio.sleep(SCHEDULE_CHECK_INTERVAL)
