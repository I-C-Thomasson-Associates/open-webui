import json
import logging
import time
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from open_webui.internal.db import get_session

from open_webui.models.schedules import (
    ScheduleForm,
    ScheduleModel,
    ScheduleResponse,
    ScheduleUserResponse,
    ScheduleRunModel,
    Schedules,
)
from open_webui.utils.auth import get_admin_user, get_verified_user
from open_webui.utils.access_control import has_permission
from open_webui.utils.chat import generate_chat_completion

from open_webui.constants import ERROR_MESSAGES

log = logging.getLogger(__name__)

router = APIRouter()


############################
# GetSchedules
############################


@router.get("/", response_model=list[ScheduleUserResponse])
async def get_schedules(
    request: Request,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    if user.role == "admin":
        return Schedules.get_schedules(db=db)
    else:
        return Schedules.get_schedules_by_user_id(user.id, db=db)


############################
# CreateNewSchedule
############################


@router.post("/create", response_model=Optional[ScheduleResponse])
async def create_new_schedule(
    request: Request,
    form_data: ScheduleForm,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    if user.role != "admin" and not has_permission(
        user.id,
        "workspace.schedules",
        request.app.state.config.USER_PERMISSIONS,
        db=db,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    schedule_id = str(uuid4())
    schedule = Schedules.insert_new_schedule(schedule_id, user.id, form_data, db=db)

    if schedule:
        return schedule
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT("Error creating schedule"),
        )


############################
# GetScheduleById
############################


@router.get("/id/{id}", response_model=Optional[ScheduleUserResponse])
async def get_schedule_by_id(
    id: str, user=Depends(get_verified_user), db: Session = Depends(get_session)
):
    schedule = Schedules.get_schedule_by_id(id, db=db)

    if schedule:
        if user.role == "admin" or schedule.user_id == user.id:
            return schedule
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.ACCESS_PROHIBITED,
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# UpdateScheduleById
############################


@router.post("/id/{id}/update", response_model=Optional[ScheduleModel])
async def update_schedule_by_id(
    request: Request,
    id: str,
    form_data: ScheduleForm,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    schedule = Schedules.get_schedule_by_id(id, db=db)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if schedule.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    updated = form_data.model_dump()
    schedule = Schedules.update_schedule_by_id(id, updated, db=db)

    if schedule:
        return schedule
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT("Error updating schedule"),
        )


############################
# DeleteScheduleById
############################


@router.delete("/id/{id}/delete", response_model=bool)
async def delete_schedule_by_id(
    request: Request,
    id: str,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    schedule = Schedules.get_schedule_by_id(id, db=db)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if schedule.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    result = Schedules.delete_schedule_by_id(id, db=db)
    return result


############################
# RunSchedule (manual trigger)
############################


@router.post("/id/{id}/run", response_model=Optional[ScheduleRunModel])
async def run_schedule(
    request: Request,
    id: str,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    schedule = Schedules.get_schedule_by_id(id, db=db)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if schedule.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    run_id = str(uuid4())
    run = Schedules.insert_new_run(run_id, id, db=db)

    if run:
        # Mark as running
        Schedules.update_run_by_id(
            run_id,
            {"status": "running", "started_at": int(time.time())},
            db=db,
        )

        try:
            models = request.app.state.MODELS
            model_id = schedule.model_id

            if model_id not in models:
                raise ValueError(f"Model '{model_id}' not found")

            # Build features dict from capabilities stored in meta
            meta = schedule.meta or {}
            capabilities = meta.get("capabilities", {})
            features = {}
            for key in ["web_search", "code_interpreter", "image_generation"]:
                if capabilities.get(key):
                    features[key] = True

            payload = {
                "model": model_id,
                "messages": [{"role": "user", "content": schedule.prompt}],
                "stream": False,
                "tool_ids": schedule.tools if schedule.tools else [],
                "filter_ids": schedule.filters if schedule.filters else [],
                "features": features,
                "metadata": {
                    "task": "schedule_run",
                    "schedule_id": id,
                },
            }

            response = await generate_chat_completion(
                request, form_data=payload, user=user
            )

            # Extract AI response content
            if isinstance(response, dict):
                choices = response.get("choices", [])
                if choices and choices[0].get("message", {}).get("content"):
                    ai_content = choices[0]["message"]["content"]
                else:
                    ai_content = "No response generated by the model."
            elif isinstance(response, JSONResponse):
                body = response.body.decode("utf-8")
                data = json.loads(body)
                choices = data.get("choices", [])
                if choices and choices[0].get("message", {}).get("content"):
                    ai_content = choices[0]["message"]["content"]
                else:
                    ai_content = "No response generated by the model."
            else:
                ai_content = str(response)

            result_text = (
                f"## Schedule: {schedule.name}\n\n"
                f"**Model:** {schedule.model_id}\n"
                f"**Prompt:** {schedule.prompt}\n"
                f"**Tools:** {', '.join(schedule.tools) if schedule.tools else 'None'}\n\n"
                f"---\n\n"
                f"## AI Response\n\n"
                f"{ai_content}\n\n"
                f"---\n\n"
                f"*Completed at {time.strftime('%Y-%m-%d %H:%M:%S')}*"
            )

            run = Schedules.update_run_by_id(
                run_id,
                {
                    "status": "completed",
                    "result": result_text,
                    "completed_at": int(time.time()),
                },
                db=db,
            )

        except Exception as e:
            log.exception(f"Error executing schedule '{schedule.name}': {e}")
            error_text = (
                f"## Schedule: {schedule.name}\n\n"
                f"**Model:** {schedule.model_id}\n"
                f"**Prompt:** {schedule.prompt}\n\n"
                f"---\n\n"
                f"## Error\n\n"
                f"Failed to execute: {str(e)}\n\n"
                f"---\n\n"
                f"*Failed at {time.strftime('%Y-%m-%d %H:%M:%S')}*"
            )
            run = Schedules.update_run_by_id(
                run_id,
                {
                    "status": "failed",
                    "result": error_text,
                    "completed_at": int(time.time()),
                },
                db=db,
            )

        return run
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT("Error running schedule"),
        )


############################
# GetScheduleRuns
############################


@router.get("/id/{id}/runs", response_model=list[ScheduleRunModel])
async def get_schedule_runs(
    id: str,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    schedule = Schedules.get_schedule_by_id(id, db=db)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if schedule.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    return Schedules.get_runs_by_schedule_id(id, db=db)


############################
# GetScheduleRunById
############################


@router.get("/runs/{run_id}", response_model=Optional[ScheduleRunModel])
async def get_schedule_run_by_id(
    run_id: str,
    user=Depends(get_verified_user),
    db: Session = Depends(get_session),
):
    run = Schedules.get_run_by_id(run_id, db=db)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    schedule = Schedules.get_schedule_by_id(run.schedule_id, db=db)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )

    if schedule.user_id != user.id and user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.UNAUTHORIZED,
        )

    return run
