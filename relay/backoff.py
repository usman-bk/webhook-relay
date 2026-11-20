import random


def delay_for(attempt: int, base: float, cap: float, rng: random.Random | None = None) -> float:
    """Seconds to wait after attempt number `attempt` (1 based) failed.

    Exponential with "equal jitter": half the step is fixed and half is random,
    so a burst of failures does not come back in lockstep and the wait is never
    close to zero.
    """
    step = min(cap, base * 2 ** (attempt - 1))
    r = rng or random
    return step / 2 + r.uniform(0, step / 2)
