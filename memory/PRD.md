# SOC Sentinel Blue — Product Requirements

## Problem statement
Aplicativo móvel para analistas de cyber segurança (blue team), com triagem operacional, resposta a incidentes, análise assistida por IA, consulta rápida de IOCs e estudo contínuo.

## Architecture
- Expo/React Native frontend with FastAPI backend and MongoDB persistence.
- JWT email/password session stored in Expo SecureStore; corporate SSO button is prepared but provider configuration is still pending.
- AI analysis (incidents, Q&A copilot, IOC triage) runs server-side with GPT-5.6 Terra through Emergent integrations, accepting text/log context and base64 image input.

## User personas
- Analista SOC/blue team em turno, que precisa classificar alertas com rapidez e rastreabilidade.
- Líder de resposta a incidentes, que precisa revisar relatórios e reabrir análises anteriores.
- Profissional de segurança em treinamento, que precisa revisar fundamentos e playbooks.

## Core requirements (static)
- Incident dashboard and manual incident intake.
- Green/yellow/red traffic-light analysis with analyst review required.
- Response checklist, evidence notes, editable report draft with revert-to-AI-draft.
- Quick IOC lookup (IPv4, domain, URL, MD5/SHA1/SHA256, email) with persistent history.
- Side drawer for AI questions, cyber study library, analysis history, IOC lookup, settings, and session controls.
- Dark SOC theme by default with a manual light-theme toggle.

## Implemented
- 2026-11-09: Built authenticated workspace, dashboard metrics, incident creation, checklist, evidence notes, and manual review flow.
- 2026-11-09: Added GPT-5.6 Terra text/image-assisted incident classification and SOC Q&A copilot.
- 2026-11-09: Added persistent analysis history with timestamps, incident context, classification, findings, and next steps.
- 2026-11-09: Added seeded cyber study library and side drawer navigation.
- 2026-11-10: Added quick IOC lookup endpoint with regex-based type detection, LLM triage, persistent history and dedicated drawer panel.
- 2026-11-10: Refined manual report review: editor shows last-reviewed timestamp, keeps the original AI draft so analysts can revert, and the save button toggles between "Marcar como revisado" / "Atualizar revisão".

## Prioritized backlog
- P0: Finish corporate/Google SSO provider configuration and end-to-end verification.
- P1: Add IOC enrichment connectors (VirusTotal, AbuseIPDB, URLScan) and bulk CSV lookup.
- P1: Add report export (PDF) and secure evidence file uploads.
- P2: Push notifications, saved study progress, offline draft queue, analyst roles.

## Remaining next tasks
1. Validate IOC + report flows with the Expo testing agent.
2. Configure a real corporate SSO provider when tenant/client details are available.
3. Add analyst roles and organization-level incident sharing.
