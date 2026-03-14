-- Migration: table proxy_metrics pour les métriques du vaultaire_proxy
-- À exécuter sur la base vaultaire si la table n'existe pas (ou déjà créée via Create_DataBase).
-- Date: 2026-03

CREATE TABLE IF NOT EXISTS proxy_metrics (
    id_metric INT AUTO_INCREMENT PRIMARY KEY,
    proxy_hostname VARCHAR(255) NOT NULL,
    proxy_ip VARCHAR(45) NOT NULL,
    metric_type VARCHAR(64) NOT NULL,
    metric_value DOUBLE NOT NULL,
    extra JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_proxy (proxy_hostname),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
