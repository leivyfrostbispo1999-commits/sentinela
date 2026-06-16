import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. CSS ABSOLUTO - DESTRUIÇÃO DE GRIDS E FLEX ROWS
css_radical = """
    /* TRUE CSS MASONRY - RECONSTRUÇÃO ARQUITETURAL */
    .masonry-root {
        column-count: 2;
        column-gap: 16px;
        width: 100%;
        display: block !important;
    }

    @media (max-width: 1400px) {
        .masonry-root {
            column-count: 1;
        }
    }

    .widget-card {
        break-inside: avoid;
        -webkit-column-break-inside: avoid;
        page-break-inside: avoid;

        display: inline-block;
        vertical-align: top;
        width: 100%;
        margin: 0 0 16px;

        height: auto !important;
        min-height: unset !important;
        max-height: unset !important;

        flex: unset !important;
        grid-row: unset !important;
        align-self: start !important;
        
        border: 1px solid var(--border-subtle);
        border-radius: 2px;
        background: var(--surface-primary);
        contain: layout paint;
    }

    /* Reset de containers internos que podem estar forçando altura */
    .panel, .card, .incident-overview, .rule-editor, .feed, .timeline-compact, .rank-list {
        height: auto !important;
        min-height: unset !important;
        max-height: unset !important;
        flex: unset !important;
    }

    /* Scrollbars internas somente para não estourar a página inteira se necessário, 
       mas priorizando o fluxo Masonry */
    .feed-container { max-height: 500px; overflow: auto; }
    .timeline-container { max-height: 600px; overflow-y: auto; }
    
    /* Performance */
    .widget-card { transform: translateZ(0); will-change: transform; }
"""

# Remover TUDO do style anterior e injetar o novo
content = re.sub(r'<style>.*?</style>', "<style>\n" + css_radical + "\n</style>", content, flags=re.DOTALL)

# 2. HTML ABSOLUTO - TODOS OS WIDGETS FILHOS DIRETOS DO ROOT
# Localizar o início do banner e o fim do main
body_start_marker = '<div class="critical-banner" id="criticalBanner">INCIDENTE CRÍTICO EM ANDAMENTO</div>'
body_end_marker = '</main>'

new_body_structure = """<div class="masonry-root" id="dashboard-masonry">
    <!-- WIDGET 1: Fila de Incidentes -->
    <section class="widget-card" id="incidentsListPanel">
        <div class="panel-head"><h2 class="panel-title">Fila de Incidentes</h2><div class="live" id="incidentsStatus">...</div></div>
        <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
            <select class="select" id="incidentStatusFilter" style="flex:1;"><option value="all">Status</option></select>
        </div>
        <div class="rank-list" id="incidentsList"></div>
    </section>

    <!-- WIDGET 2: Workspace Investigativo & Timeline -->
    <section class="widget-card" id="incidentPanel">
        <div class="panel-head"><h2 class="panel-title">Workspace Investigativo</h2><div class="live">LIVE</div></div>
        <div id="attackChainWrapper" style="padding:8px; border-bottom: 1px solid var(--border-subtle); display:none;">
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

    <!-- WIDGET 3: AI Intelligence -->
    <section class="widget-card" id="aiIntelligencePanel">
        <div class="panel-head"><h2 class="panel-title">AI Anomaly & Scores</h2></div>
        <div id="ai-scores-list" class="rank-list"></div>
    </section>

    <!-- WIDGET 4: SOAR Automation -->
    <section class="widget-card" id="soarPanel">
        <div class="panel-head"><h2 class="panel-title">SOAR Response Status</h2></div>
        <div id="soar-status" class="rank-list"></div>
    </section>

    <!-- WIDGET 5: Operational Alert Stream -->
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

    <!-- WIDGET 6: Threat Hunting -->
    <section class="widget-card" id="huntingConsole">
        <div class="panel-head"><h2 class="panel-title">Threat Hunting</h2></div>
        <div class="query-row">
            <input class="search" id="huntingQuery" placeholder="Query..." style="flex:1;">
            <button class="button" id="huntingSearchButton">HUNT</button>
        </div>
        <div class="rank-list" id="huntingResults"></div>
    </section>

    <!-- WIDGET 7: IOC Enrichment -->
    <section class="widget-card" id="iocPanel">
        <div class="panel-head"><h2 class="panel-title">IOC Enrichment</h2></div>
        <div class="query-row">
            <input class="search" id="iocValue" placeholder="IP, host, hash..." style="flex:1;">
            <button class="button" id="iocLookupButton">ENRICH</button>
        </div>
        <div class="rank-list" id="iocResults"></div>
    </section>

    <!-- WIDGET 8: Replay & Retention -->
    <section class="widget-card" id="replayPanel">
        <div class="panel-head"><h2 class="panel-title">Replay & Retention Jobs</h2></div>
        <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
            <button class="button" id="replayButton">Iniciar Replay 24h</button>
        </div>
        <div class="rank-list" id="replayResults"></div>
    </section>

    <!-- WIDGET 9: Geo Threat Map -->
    <section class="widget-card" id="mapPanel">
        <div class="panel-head"><h2 class="panel-title">Geo Threat Map</h2></div>
        <div class="map-stage" id="mapStage">
            <svg class="world" viewBox="0 0 900 430"><path d="M92 148l62-36 84 22 24 47-42 32-83-8-68-32z"></path></svg>
            <div id="lines"></div><div id="points"></div>
        </div>
    </section>

    <!-- WIDGET 10: Rule Studio Enterprise -->
    <section class="widget-card" id="ruleStudio">
        <div class="panel-head"><h2 class="panel-title">Rule Studio Enterprise</h2></div>
        <div class="rule-editor">
            <div id="monacoEditor"></div>
            <div class="toolbar" style="margin-top:4px;">
                <button class="button" id="validateRuleButton">Validar</button>
                <button class="button demo" id="saveRuleButton">Salvar Regra</button>
            </div>
            <div id="ruleStudioResults" class="rank-list"></div>
        </div>
    </section>

    <!-- WIDGET 11: RBAC & Administration -->
    <section class="widget-card" id="adminUsersPanel">
        <div class="panel-head"><h2 class="panel-title">RBAC & Users</h2><div class="live" id="usersStatus">...</div></div>
        <div class="rank-list" id="usersList"></div>
    </section>
</div>
"""

# Injetar o novo corpo no main
content = re.sub(re.escape(body_start_marker) + r'.*?' + re.escape(body_end_marker), body_start_marker + "\n" + new_body_structure + "\n" + body_end_marker, content, flags=re.DOTALL)

# 3. JS: Ajustar IDs e garantir que nada quebre
# Garantir que a Cadeia de Ataque seja ocultada se vazia
logic_fix = """
        // Lógica de packing Masonry: ocultar se vazio
        function checkContent(id, wrapperId) {
            const el = document.getElementById(id);
            const wrap = document.getElementById(wrapperId || id);
            if (el && wrap) {
                const hasData = el.innerHTML.trim() !== "" && !el.innerHTML.includes("empty-state");
                wrap.style.display = hasData ? "block" : "none";
            }
        }
        
        const oldRefreshCorrelation = refreshCorrelation;
        refreshCorrelation = async function() {
            await oldRefreshCorrelation();
            checkContent('attackChains', 'attackChainWrapper');
        };
"""

# Injetar antes do fim do script
content = content.replace("connectSocketIO();", logic_fix + "\n        connectSocketIO();")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Estrutura destruída e True Masonry REAL reconstruído.")
