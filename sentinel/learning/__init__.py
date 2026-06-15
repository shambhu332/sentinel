"""Per-app learning — improves repeat scans of the same APK."""
from sentinel.learning.feedback import FeedbackLoop
from sentinel.learning.ml_strategy import MLStrategySelector, train_from_profiles
from sentinel.learning.profile_store import (
    AppLearningProfile,
    AppProfileStore,
    default_store,
)
from sentinel.learning.strategy import (
    FeedbackAgent,
    StrategyRecord,
    StrategySelector,
    applies_strategy,
)

__all__ = [
    "AppLearningProfile",
    "AppProfileStore",
    "FeedbackAgent",
    "FeedbackLoop",
    "MLStrategySelector",
    "StrategyRecord",
    "StrategySelector",
    "applies_strategy",
    "default_store",
    "train_from_profiles",
]
