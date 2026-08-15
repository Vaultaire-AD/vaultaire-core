package dbgpo

const policySelect = `SELECT id_gpo, gpo_name, scope, description, version, enabled, drift_mode, created_at, updated_at FROM gpo`
