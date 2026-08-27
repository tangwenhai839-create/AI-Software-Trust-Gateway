"""Dynamic analysis provider boundary.

Dynamic execution is deliberately opt-in. Providers must guarantee isolation;
the core application never falls back to executing untrusted code directly.
"""
