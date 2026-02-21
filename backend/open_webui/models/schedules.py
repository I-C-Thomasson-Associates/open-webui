import logging
import time
from typing import Optional

from sqlalchemy.orm import Session
from open_webui.internal.db import Base, JSONField, get_db, get_db_context
from open_webui.models.users import Users, UserResponse

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import BigInteger, Boolean, Column, String, Text

log = logging.getLogger(__name__)

####################
# Schedule DB Schema
####################


class Schedule(Base):
    __tablename__ = "schedule"

    id = Column(String, primary_key=True, unique=True)
    user_id = Column(String)
    name = Column(Text)
    description = Column(Text, nullable=True)

    model_id = Column(String)
    prompt = Column(Text)
    tools = Column(JSONField, nullable=True)

    frequency = Column(String)  # once, daily, weekly, monthly
    scheduled_at = Column(BigInteger, nullable=True)
    is_active = Column(Boolean, default=True)
    meta = Column(JSONField, nullable=True)

    updated_at = Column(BigInteger)
    created_at = Column(BigInteger)


class ScheduleRun(Base):
    __tablename__ = "schedule_run"

    id = Column(String, primary_key=True, unique=True)
    schedule_id = Column(String)
    status = Column(String)  # pending, running, completed, failed
    result = Column(Text, nullable=True)

    started_at = Column(BigInteger, nullable=True)
    completed_at = Column(BigInteger, nullable=True)
    created_at = Column(BigInteger)


####################
# Pydantic Models
####################


class ScheduleMeta(BaseModel):
    description: Optional[str] = None


class ScheduleModel(BaseModel):
    id: str
    user_id: str
    name: str
    description: Optional[str] = None

    model_id: str
    prompt: str
    tools: Optional[list[str]] = None

    frequency: str
    scheduled_at: Optional[int] = None
    is_active: bool = True
    meta: Optional[dict] = None

    updated_at: int
    created_at: int

    model_config = ConfigDict(from_attributes=True)


class ScheduleUserModel(ScheduleModel):
    user: Optional[UserResponse] = None


class ScheduleResponse(BaseModel):
    id: str
    user_id: str
    name: str
    description: Optional[str] = None

    model_id: str
    prompt: str
    tools: Optional[list[str]] = None

    frequency: str
    scheduled_at: Optional[int] = None
    is_active: bool = True
    meta: Optional[dict] = None

    updated_at: int
    created_at: int


class ScheduleUserResponse(ScheduleResponse):
    user: Optional[UserResponse] = None

    model_config = ConfigDict(extra="allow")


class ScheduleRunModel(BaseModel):
    id: str
    schedule_id: str
    status: str
    result: Optional[str] = None

    started_at: Optional[int] = None
    completed_at: Optional[int] = None
    created_at: int

    model_config = ConfigDict(from_attributes=True)


####################
# Forms
####################


class ScheduleForm(BaseModel):
    name: str
    description: Optional[str] = None
    model_id: str
    prompt: str
    tools: Optional[list[str]] = None
    frequency: str  # once, daily, weekly, monthly
    scheduled_at: Optional[int] = None
    is_active: bool = True
    meta: Optional[dict] = None


class ScheduleRunForm(BaseModel):
    schedule_id: str
    status: str = "pending"


####################
# Tables
####################


class SchedulesTable:
    def insert_new_schedule(
        self,
        id: str,
        user_id: str,
        form_data: ScheduleForm,
        db: Optional[Session] = None,
    ) -> Optional[ScheduleModel]:
        with get_db_context(db) as db:
            try:
                result = Schedule(
                    **{
                        **form_data.model_dump(),
                        "id": id,
                        "user_id": user_id,
                        "updated_at": int(time.time()),
                        "created_at": int(time.time()),
                    }
                )
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return ScheduleModel.model_validate(result)
                else:
                    return None
            except Exception as e:
                log.exception(f"Error creating a new schedule: {e}")
                return None

    def get_schedule_by_id(
        self, id: str, db: Optional[Session] = None
    ) -> Optional[ScheduleModel]:
        try:
            with get_db_context(db) as db:
                schedule = db.get(Schedule, id)
                return ScheduleModel.model_validate(schedule) if schedule else None
        except Exception:
            return None

    def get_schedules(self, db: Optional[Session] = None) -> list[ScheduleUserModel]:
        with get_db_context(db) as db:
            all_schedules = (
                db.query(Schedule).order_by(Schedule.updated_at.desc()).all()
            )

            user_ids = list(set(s.user_id for s in all_schedules))
            users = Users.get_users_by_user_ids(user_ids, db=db) if user_ids else []
            users_dict = {user.id: user for user in users}

            schedules = []
            for schedule in all_schedules:
                user = users_dict.get(schedule.user_id)
                schedules.append(
                    ScheduleUserModel.model_validate(
                        {
                            **ScheduleModel.model_validate(schedule).model_dump(),
                            "user": user.model_dump() if user else None,
                        }
                    )
                )
            return schedules

    def get_schedules_by_user_id(
        self, user_id: str, db: Optional[Session] = None
    ) -> list[ScheduleUserModel]:
        with get_db_context(db) as db:
            all_schedules = (
                db.query(Schedule)
                .filter(Schedule.user_id == user_id)
                .order_by(Schedule.updated_at.desc())
                .all()
            )

            user_ids = list(set(s.user_id for s in all_schedules))
            users = Users.get_users_by_user_ids(user_ids, db=db) if user_ids else []
            users_dict = {user.id: user for user in users}

            schedules = []
            for schedule in all_schedules:
                user = users_dict.get(schedule.user_id)
                schedules.append(
                    ScheduleUserModel.model_validate(
                        {
                            **ScheduleModel.model_validate(schedule).model_dump(),
                            "user": user.model_dump() if user else None,
                        }
                    )
                )
            return schedules

    def update_schedule_by_id(
        self, id: str, updated: dict, db: Optional[Session] = None
    ) -> Optional[ScheduleModel]:
        try:
            with get_db_context(db) as db:
                db.query(Schedule).filter_by(id=id).update(
                    {**updated, "updated_at": int(time.time())}
                )
                db.commit()
                schedule = db.query(Schedule).get(id)
                db.refresh(schedule)
                return ScheduleModel.model_validate(schedule)
        except Exception:
            return None

    def delete_schedule_by_id(self, id: str, db: Optional[Session] = None) -> bool:
        try:
            with get_db_context(db) as db:
                # Delete associated runs first
                db.query(ScheduleRun).filter_by(schedule_id=id).delete()
                db.query(Schedule).filter_by(id=id).delete()
                db.commit()
                return True
        except Exception:
            return False

    # Schedule Run methods

    def insert_new_run(
        self,
        id: str,
        schedule_id: str,
        db: Optional[Session] = None,
    ) -> Optional[ScheduleRunModel]:
        with get_db_context(db) as db:
            try:
                result = ScheduleRun(
                    **{
                        "id": id,
                        "schedule_id": schedule_id,
                        "status": "pending",
                        "created_at": int(time.time()),
                    }
                )
                db.add(result)
                db.commit()
                db.refresh(result)
                if result:
                    return ScheduleRunModel.model_validate(result)
                else:
                    return None
            except Exception as e:
                log.exception(f"Error creating a new schedule run: {e}")
                return None

    def get_run_by_id(
        self, id: str, db: Optional[Session] = None
    ) -> Optional[ScheduleRunModel]:
        try:
            with get_db_context(db) as db:
                run = db.get(ScheduleRun, id)
                return ScheduleRunModel.model_validate(run) if run else None
        except Exception:
            return None

    def get_runs_by_schedule_id(
        self, schedule_id: str, db: Optional[Session] = None
    ) -> list[ScheduleRunModel]:
        with get_db_context(db) as db:
            runs = (
                db.query(ScheduleRun)
                .filter_by(schedule_id=schedule_id)
                .order_by(ScheduleRun.created_at.desc())
                .all()
            )
            return [ScheduleRunModel.model_validate(run) for run in runs]

    def update_run_by_id(
        self, id: str, updated: dict, db: Optional[Session] = None
    ) -> Optional[ScheduleRunModel]:
        try:
            with get_db_context(db) as db:
                db.query(ScheduleRun).filter_by(id=id).update(updated)
                db.commit()
                run = db.query(ScheduleRun).get(id)
                db.refresh(run)
                return ScheduleRunModel.model_validate(run)
        except Exception:
            return None

    def delete_run_by_id(self, id: str, db: Optional[Session] = None) -> bool:
        try:
            with get_db_context(db) as db:
                db.query(ScheduleRun).filter_by(id=id).delete()
                db.commit()
                return True
        except Exception:
            return False


Schedules = SchedulesTable()
