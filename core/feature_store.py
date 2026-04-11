import logging
import os
import time
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GraphMetrics:
    user_device_ratio: float = 0.0
    device_user_ratio: float = 0.0
    req_rate_5m: float = 0.0
    source: str = "disabled"


class RedisFeatureStore:
    """Redis-backed lightweight graph features for account/device/rate dimensions."""

    def __init__(self):
        self.enabled = False
        import redis  # 避免型別循環

        self.client: redis.Redis | None = None
        self.window_seconds = int(os.getenv("REDIS_FEATURE_WINDOW_SECONDS", "300"))
        self.key_ttl_seconds = int(os.getenv("REDIS_FEATURE_TTL_SECONDS", "86400"))
        self._init_client()

    def _init_client(self):
        redis_url = os.getenv("REDIS_URL", "").strip()
        if not redis_url:
            logger.info("REDIS_URL 未設定，關聯圖特徵降級為停用。")
            return

        try:
            import redis
            from typing import cast

            self.client = cast(
                redis.Redis,
                redis.Redis.from_url(redis_url, decode_responses=True),  # type: ignore
            )  # type: ignore
            self.client.ping()  # type: ignore
            self.enabled = True
            logger.info("Redis Feature Store 已連線。")
        except Exception as exc:
            logger.warning("Redis Feature Store 連線失敗，降級停用: %s", exc)
            self.enabled = False
            self.client = None

    def _safe_key(self, prefix: str, value: str) -> str:
        return f"ms:{prefix}:{value}"

    def record_observation(
        self, user_id: str, device_id: str, now_ts: float | None = None
    ):
        if not self.enabled or not self.client:
            return

        now_ts = now_ts if now_ts is not None else time.time()
        now_ms = int(now_ts * 1000)

        user_devices_key = self._safe_key("user_devices", user_id)
        device_users_key = self._safe_key("device_users", device_id)
        user_events_key = self._safe_key("user_events", user_id)

        event_member = f"{now_ms}:{device_id}:{time.time_ns()}"

        try:
            pipeline: Any = self.client.pipeline(transaction=False)  # type: ignore
            pipeline.sadd(user_devices_key, device_id)
            pipeline.expire(user_devices_key, self.key_ttl_seconds)

            pipeline.sadd(device_users_key, user_id)
            pipeline.expire(device_users_key, self.key_ttl_seconds)

            pipeline.zadd(user_events_key, {event_member: now_ts})
            pipeline.zremrangebyscore(user_events_key, 0, now_ts - self.window_seconds)
            pipeline.expire(user_events_key, self.key_ttl_seconds)
            pipeline.execute()
        except Exception as exc:
            logger.warning("Redis record_observation 失敗，忽略本次寫入: %s", exc)

    def get_metrics(
        self, user_id: str, device_id: str, now_ts: float | None = None
    ) -> GraphMetrics:
        if not self.enabled or not self.client:
            return GraphMetrics(source="disabled")

        now_ts = now_ts if now_ts is not None else time.time()

        user_devices_key = self._safe_key("user_devices", user_id)
        device_users_key = self._safe_key("device_users", device_id)
        user_events_key = self._safe_key("user_events", user_id)

        try:
            pipeline: Any = self.client.pipeline(transaction=False)  # type: ignore
            pipeline.scard(user_devices_key)
            pipeline.scard(device_users_key)
            pipeline.zcount(user_events_key, now_ts - self.window_seconds, now_ts)
            user_devices_count, device_users_count, events_in_window = (
                pipeline.execute()
            )

            req_rate = float(events_in_window) / float(self.window_seconds)
            return GraphMetrics(
                user_device_ratio=float(user_devices_count),
                device_user_ratio=float(device_users_count),
                req_rate_5m=round(req_rate, 6),
                source="redis",
            )
        except Exception as exc:
            logger.warning("Redis get_metrics 失敗，回退為 0: %s", exc)
            return GraphMetrics(source="degraded")


_feature_store = RedisFeatureStore()


def get_feature_store() -> RedisFeatureStore:
    return _feature_store
