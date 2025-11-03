from rest_framework.throttling import UserRateThrottle, AnonRateThrottle

class UserFiveCallsPerMinute(UserRateThrottle):
    scope = 'five'


class EmailTwoCallsPerMinute(AnonRateThrottle, UserRateThrottle):
    scope = 'two'


class ResetEmailTwoCallsPerHour(AnonRateThrottle, UserRateThrottle):
    scope = 'reset-email'