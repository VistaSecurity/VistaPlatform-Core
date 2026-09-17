# Certificate compliance refresh

Certificate compliance findings refresh after inventory changes and every 12 hours for certificates near or past a published policy threshold. The first scheduled pass starts three minutes after compliance-engine starts. The scan derives its window from published certificate-expiration controls, including zero-day and fractional-day thresholds, and includes a one-day boundary margin.

This updates findings and framework scores; it does not add notification thresholds. Certificate expiry notifications retain their own policy. Operators can set `COMPLIANCE_CERT_BAND_SCAN_ENABLED=false` on compliance-engine to stop the scheduled pass; event-driven evaluation continues, but findings can then become stale as certificates age.
