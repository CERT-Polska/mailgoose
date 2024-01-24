import dataclasses
import datetime
import json
from typing import Any, Dict, Optional

import dacite
from libmailgoose.scan import ScanResult
from redis import Redis

from common.config import Config

from .logging import build_logger

REDIS = Redis.from_url(Config.Data.REDIS_URL)

LOGGER = build_logger(__name__)


class JSONEncoderAdditionalTypes(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, datetime.datetime):
            return o.isoformat()
        return super().default(o)


def save_check_results(
    envelope_domain: str,
    from_domain: str,
    dkim_domain: Optional[str],
    result: Optional[ScanResult],
    error: Optional[str],
    rescan_url: str,
    message_recipient_username: Optional[str],
    token: str,
) -> None:
    # We don't use HSET or HMSET, as result is a recursive dict, and values that can be stored
    # using HSET/HMSET are bytes, string, int or float, so we still wouldn't avoid serialization.
    REDIS.set(
        f"check-results-{token}",
        json.dumps(
            {
                "created_at": datetime.datetime.now(),
                "envelope_domain": envelope_domain,
                "from_domain": from_domain,
                "dkim_domain": dkim_domain,
                "result": result,
                "error": error,
                "rescan_url": rescan_url,
                "message_recipient_username": message_recipient_username,
            },
            indent=4,
            cls=JSONEncoderAdditionalTypes,
        ),
    )


def load_check_results(token: str) -> Optional[Dict[str, Any]]:
    data = REDIS.get(f"check-results-{token}")

    if not data:
        return None

    result: Dict[str, Any] = json.loads(data)

    result["created_at"] = datetime.datetime.fromisoformat(result["created_at"])
    if result["result"]:
        result["result"]["timestamp"] = datetime.datetime.fromisoformat(result["result"]["timestamp"])
        if result["result"]["message_timestamp"]:
            result["result"]["message_timestamp"] = datetime.datetime.fromisoformat(
                result["result"]["message_timestamp"]
            )
        try:
            dacite.from_dict(
                data_class=ScanResult,
                data=result["result"],
            )
        except dacite.WrongTypeError:
            LOGGER.exception("Wrong type detected when deserializing")

        # As we stored what we got from the check module, we allow bad types here, logging
        # instead of raising
        result["result"] = dacite.from_dict(
            data_class=ScanResult,
            data=result["result"],
            config=dacite.Config(check_types=False),
        )

    result["age_threshold_minutes"] = Config.UI.OLD_CHECK_RESULTS_AGE_MINUTES
    result["is_old"] = (
        datetime.datetime.now() - result["created_at"]
    ).total_seconds() > 60 * Config.UI.OLD_CHECK_RESULTS_AGE_MINUTES
    return result
