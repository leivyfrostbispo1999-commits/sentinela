import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. DESTRUIÇÃO TOTAL DE CSS ANTIGO E WRAPPERS
radical_css = """
    /* TRUE CSS MASONRY - ZERO ALTURA FANTASMA */
    .dashboard-masonry {
        column-count: 2;
        column-gap: 16px;
        padding: 16px;
        display: block !important;
        width: 100%;
        box-sizing: border-box;
    }

    @media (max-width: 1400px) {
        .dashboard-masonry {
            column-count: 1;
        }
    }

    .widget-card {
        display: inline-block;
        vertical-align: top;
        width: 100%;
        margin: 0 0 16px;
        
        break-inside: avoid;
        -webkit-column-break-inside: avoid;
        page-break-inside: avoid;

        height: auto !important;
        min-height: 0 !important;
        max-height: none !important;

        flex: unset !important;
        grid-row: unset !important;
        align-self: start !important;
        
        border: 1px solid var(--border-subtle);
        border-radius: 2px;
        background: var(--surface-primary);
        contain: layout paint;
    }

    /* Garantir que nada interno force altura fantasmagórica */
    .widget-card > * {
        height: auto !important;
        min-height: 0 !important;
    }

    .feed-container, .timeline-container, .rank-list {
        max-height: 500px;
        overflow-y: auto;
    }
"""

# Limpar o bloco <style> completamente
content = re.sub(r'<style>.*?</style>', "<style>\n" + radical_css + "\n</style>", content, flags=re.DOTALL)

# 2. RECONSTRUÇÃO ATÔMICA DO HTML
body_start = '<div class="critical-banner" id="criticalBanner">INCIDENTE CRÍTICO EM ANDAMENTO</div>'
body_end = '</main>'

new_masonry_html = """<div class="dashboard-masonry" id="dashboard-masonry">
    <!-- FILHOS DIRETOS SEM WRAPPERS -->
    
    <section class="widget-card" id="incidentsListPanel">
        <div class="panel-head"><h2 class="panel-title">Fila de Incidentes</h2><div class="live" id="incidentsStatus">...</div></div>
        <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
            <select class="select" id="incidentStatusFilter" style="flex:1;"><option value="all">Status</option></select>
        </div>
        <div class="rank-list" id="incidentsList"></div>
    </section>

    <section class="widget-card" id="incidentPanel">
        <div class="panel-head"><h2 class="panel-title">Workspace Investigativo</h2><div class="live">LIVE</div></div>
        <div id="attackChainWrapper" style="padding:8px; border-bottom: 1px solid var(--border-subtle);">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span class="rail-label">Atacante:</span>
                <strong id="attackerIp">--</strong>
            </div>
            <div class="mitre-flow" id="attackChains"></div>
        </div>
        <div class="timeline-container">
            <div class="timeline-compact" id="enterpriseTimeline"></div>
        </div>
    </section>

    <section class="widget-card" id="aiIntelligencePanel">
        <div class="panel-head"><h2 class="panel-title">AI Anomaly & Scores</h2></div>
        <div id="ai-scores-list" class="rank-list"></div>
    </section>

    <section class="widget-card" id="soarPanel">
        <div class="panel-head"><h2 class="panel-title">SOAR Response Status</h2></div>
        <div id="soar-status" class="rank-list"></div>
    </section>

    <section class="widget-card" id="feedPanel">
        <div class="panel-head"><h2 class="panel-title">Operational Alert Stream</h2></div>
        <div class="feed-container">
            <div class="feed">
                <table>
                    <thead><tr><th>TIME</th><th>SOURCE &rarr; TARGET</th><th>SEV</th><th>RISK</th><th>MITRE</th><th>ACTION</th></tr></thead>
                    <tbody id="feedBody"></tbody>
                </table>
            </div>
        </div>
    </section>

    <section class="widget-card" id="huntingConsole">
        <div class="panel-head"><h2 class="panel-title">Threat Hunting</h2></div>
        <div class="query-row"><input class="search" id="huntingQuery" placeholder="Query..." style="flex:1;"><button class="button" id="huntingSearchButton">HUNT</button></div>
        <div class="rank-list" id="huntingResults"></div>
    </section>

    <section class="widget-card" id="iocPanel">
        <div class="panel-head"><h2 class="panel-title">IOC Enrichment</h2></div>
        <div class="query-row"><input class="search" id="iocValue" placeholder="IP, host, hash..." style="flex:1;"><button class="button" id="iocLookupButton">ENRICH</button></div>
        <div class="rank-list" id="iocResults"></div>
    </section>

    <section class="widget-card" id="replayPanel">
        <div class="panel-head"><h2 class="panel-title">Replay & Retention</h2></div>
        <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
            <button class="button" id="replayButton">Iniciar Replay 24h</button>
        </div>
        <div class="rank-list" id="replayResults"></div>
    </section>

    <section class="widget-card" id="mapPanel">
        <div class="panel-head"><h2 class="panel-title">Geo Threat Map</h2></div>
        <div class="map-stage" id="mapStage">
            <svg class="world" viewBox="0 0 900 430"><path d="M92 148l62-36 84 22 24 47-42 32-83-8-68-32z"></path></svg>
            <div id="lines"></div><div id="points"></div>
        </div>
    </section>

    <section class="widget-card" id="ruleStudio">
        <div class="panel-head"><h2 class="panel-title">Rule Studio Enterprise</h2></div>
        <div class="rule-editor">
            <div id="monacoEditor"></div>
            <div class="toolbar" style="margin-top:4px;"><button class="button" id="validateRuleButton">Validar</button><button class="button demo" id="saveRuleButton">Salvar</button></div>
            <div id="ruleStudioResults" class="rank-list"></div>
        </div>
    </section>

    <section class="widget-card" id="adminUsersPanel">
        <div class="panel-head"><h2 class="panel-title">RBAC & Users</h2><div class="live" id="usersStatus">...</div></div>
        <div class="rank-list" id="usersList"></div>
    </section>
</div>
"""

content = re.sub(re.escape(body_start) + r'.*?' + re.escape(body_end), body_start + "\n" + new_masonry_html + "\n" + body_end, content, flags=re.DOTALL)

# 3. LÓGICA JS: DISPLAY:NONE SE VAZIO
js_logic = """
        // True Masonry Logic: Ocultar painéis sem conteúdo real
        function enforceTrueMasonryVisibility() {
            const targets = [
                { contentId: 'attackChains', wrapperId: 'attackChainWrapper' },
                { contentId: 'replayResults', wrapperId: 'replayPanel' },
                { contentId: 'iocResults', wrapperId: 'iocPanel' },
                { contentId: 'enterpriseTimeline', wrapperId: 'incidentPanel' }
            ];
            
            targets.forEach(t => {
                const contentEl = el(t.contentId);
                const wrapperEl = el(t.wrapperId);
                if (contentEl && wrapperEl) {
                    const hasContent = contentEl.innerHTML.trim() !== "" && !contentEl.innerHTML.includes("empty-state");
                    // A Timeline e Incidentes mostramos sempre se houver IDs de incidentes, mas aqui forçamos colapso se zerado
                    wrapperEl.style.display = hasContent ? "inline-block" : "none";
                }
            });
        }
        
        // Substituir as funções de refresh para incluir a limpeza de visibilidade
        const originalRefreshIncidents = refreshIncidents;
        refreshIncidents = async function() {
            await originalRefreshIncidents();
            enforceTrueMasonryVisibility();
        };
        
        const originalRefreshCorrelation = refreshCorrelation;
        refreshCorrelation = async function() {
            await originalRefreshCorrelation();
            enforceTrueMasonryVisibility();
        };
"""

# Injetar JS
content = content.replace("connectSocketIO();", js_logic + "\n        connectSocketIO();")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Estrutura DESTRUÍDA e True Masonry FINAL reconstruído.")
