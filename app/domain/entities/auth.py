# Placeholder for domain authentication entities

class UnauthenticatedUser:
    """Represents an unauthenticated user."""
    # This class might be expanded later if needed, for example, to conform to an interface
    # or carry specific unauthenticated state, but for now, it serves as a marker.
    def __init__(self):
        self.is_authenticated = False
        self.roles = []
        self.id = None # Or a specific sentinel value

    def __str__(self):
        return "UnauthenticatedUser"

    def __repr__(self):
        return "<UnauthenticatedUser>"
