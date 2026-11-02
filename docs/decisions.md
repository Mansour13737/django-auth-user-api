# Architecture Decisions — Section 01 & 02

## ADR-001: Custom User Model
- **Decision:** Use `AbstractBaseUser` + `PermissionsMixin`, email as `USERNAME_FIELD`.
- **Reason:** Email is the login identifier; changing it after migrations is painful.
- **Rejected:** Default `User` (requires username).

## ADR-002: Separate flags
- **Decision:** Keep `is_active` and `is_email_verified` separate.
- **Reason:** Admin deactivation must not erase verification history.

## ADR-003: JWT with rotation + blacklisting
- **Decision:** Short access tokens, long refresh tokens, rotation + blacklisting enabled.
- **Reason:** Limits damage from stolen tokens and makes logout effective.

## ADR-004: Roles as a field
- **Decision:** `role` CharField (`USER`, `ADMIN`).
- **Reason:** Only two roles; `Group` is overkill for this project.

## ADR-005: `BigAutoField`
- **Decision:** Integer primary keys.
- **Reason:** Simpler for a junior portfolio; UUID noted as future improvement.