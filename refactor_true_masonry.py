import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Definir o CSS de True Masonry
masonry_css = """
    /* TRUE MASONRY PACKING ARCHITECTURE */
    .dashboard-masonry {
        column-count: 2;
        column-gap: 12px;
        width: 100%;
        orphans: 1;
        widows: 1;
    }

    .panel, .card, .widget-card {
        display: inline-block; /* Essencial para masonry column-count */
        width: 100%;
        margin-bottom: 12px;
        break-inside: avoid;
        height: fit-content;
        align-self: start;
        contain: layout paint;
        border: 1px solid var(--border-subtle);
        border-radius: 2px;
        background: var(--surface-primary);
    }

    @media (max-width: 1400px) {
        .dashboard-masonry {
            column-count: 1;
        }
    }

    /* Otimização de Performance para listas pesadas */
    #enterpriseTimeline, .feed, #incidentsList {
        transform: translateZ(0);
        will-change: transform;
    }

    /* Ajustes finos de Densidade */
    .panel-head { padding: 4px 8px; }
    .rank-item { padding: 3px 8px; }
    .feed table td, .feed table th { padding: 3px 6px; }
    
    /* Scrollbars internas para não estourar viewport */
    .feed { max-height: 450px; overflow: auto; }
    .timeline-compact { max-height: 500px; overflow-y: auto; }
    #incidentsList { max-height: 250px; overflow-y: auto; }
"""

# Substituir o bloco de CSS anterior
content = re.sub(r'/\* ARQUITETURA ADAPTATIVA DE ALTA DENSIDADE \*/.*?@media \(max-width: 1366px\) \{.*?\n\}', masonry_css, content, flags=re.DOTALL)

# 2. Reestruturar o HTML para remover wrappers horizontais e usar o masonry root
# Localizar o início dos widgets e o fim
body_start_marker = '<div class="critical-banner" id="criticalBanner">INCIDENTE CRÍTICO EM ANDAMENTO</div>'
body_end_marker = '</main>'

# Extrair todos os painéis individualmente
panels = []

# Regex para pegar cada <section class="panel ..."> ou divs que atuam como painéis
panel_matches = re.findall(r'<(section|div) class="panel.*?".*?id=".*?".*?>.*?</\1>', content, flags=re.DOTALL)

# Mas na reestruturação anterior eu usei wrappers como .workspace-left, .workspace-center, etc.
# Vou simplificar: remover TUDO entre o banner e o fim do main e reconstruir com os IDs originais.

new_masonry_body = """<div class="dashboard-masonry">
    <!-- 1. Fila de Incidentes -->
    <section class="panel essential-panel" id="incidentsListPanel">
        <div class="panel-head">
            <h2 class="panel-title">Fila de Incidentes</h2>
            <div class="live" id="incidentsStatus">...</div>
        </div>
        <div class="toolbar" style="padding: 2px 8px; border-bottom: 1px solid var(--border-subtle);">
            <select class="select" id="incidentStatusFilter" style="flex:1;"><option value="all">Status</option></select>
            <select class="select" id="incidentSeverityFilter" style="flex:1;"><option value="all">Severity</option></select>
        </div>
        <div class="rank-list" id="incidentsList"></div>
    </section>

    <!-- 2. Workspace Investigativo (Timeline & Cadeia) -->
    <section class="panel essential-panel" id="incidentPanel">
        <div class="panel-head">
            <h2 class="panel-title">Workspace Investigativo</h2>
            <div class="live">LIVE</div>
        </div>
        <div class="incident-overview" style="display:block; padding:8px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span class="rail-label">Atacante:</span>
                <strong class="rail-value" id="attackerIp">--</strong>
            </div>
            <div class="mitre-flow" id="attackChains"></div>
        </div>
        <div class="timeline-compact" id="enterpriseTimeline"></div>
    </section>

    <!-- 3. AI & SOAR Intelligence -->
    <section class="panel" id="ai-xdr-section">
        <div class="panel-head"><h2 class="panel-title">AI Anomaly & SOAR</h2></div>
        <div id="ai-scores-list" class="rank-list"></div>
        <div id="soar-status" class="rank-list"></div>
    </section>

    <!-- 4. Alert Stream (Feed) -->
    <section class="panel feed-panel" id="feedPanel">
        <div class="panel-head"><h2 class="panel-title">Operational Alert Stream</h2></div>
        <div class="feed">
            <table>
                <thead>
                    <tr>
                        <th>TIME</th>
                        <th>SOURCE &rarr; TARGET</th>
                        <th>SEV</th>
                        <th>RISK</th>
                        <th>MITRE</th>
                        <th>ACTION</th>
                    </tr>
                </thead>
                <tbody id="feedBody"></tbody>
            </table>
        </div>
    </section>

    <!-- 5. Threat Hunting -->
    <section class="panel essential-panel" id="huntingConsole">
        <div class="panel-head"><h2 class="panel-title">Threat Hunting</h2></div>
        <div class="query-row">
            <input class="search" id="huntingQuery" placeholder="Query..." style="flex:1;">
            <button class="button" id="huntingSearchButton">HUNT</button>
        </div>
        <div class="rank-list" id="huntingResults"></div>
    </section>

    <!-- 6. IOC Lookup -->
    <section class="panel" id="iocPanel">
        <div class="panel-head"><h2 class="panel-title">IOC Enrichment</h2></div>
        <div class="query-row">
            <input class="search" id="iocValue" placeholder="IP, host, hash..." style="flex:1;">
            <button class="button" id="iocLookupButton">ENRICH</button>
        </div>
        <div class="rank-list" id="iocResults"></div>
    </section>

    <!-- 7. Map & Geo Intel -->
    <section class="panel" id="mapPanel">
        <div class="panel-head"><h2 class="panel-title">Geo Threat Map</h2></div>
        <div class="map-stage" id="mapStage">
            <svg class="world" viewBox="0 0 900 430" style="opacity:0.1;"><path d="M92 148l62-36 84 22 24 47-42 32-83-8-68-32z"></path></svg>
            <div id="lines"></div>
            <div id="points"></div>
        </div>
    </section>

    <!-- 8. Analytics Grid -->
    <section class="panel" id="analyticsPanel">
        <div class="panel-head"><h2 class="panel-title">Targets Analytics</h2></div>
        <div class="rank-list" id="avgRiskList"></div>
    </section>

    <!-- 9. Rule Studio -->
    <section class="panel essential-panel" id="ruleStudio">
        <div class="panel-head"><h2 class="panel-title">Rule Studio Enterprise</h2></div>
        <div class="rule-editor">
            <div id="monacoEditor"></div>
            <div class="toolbar" style="margin-top:4px;">
                <button class="button" id="validateRuleButton">Validar</button>
                <button class="button demo" id="saveRuleButton">Salvar</button>
            </div>
        </div>
    </section>

    <!-- 10. RBAC & Users -->
    <section class="panel" id="adminUsersPanel">
        <div class="panel-head"><h2 class="panel-title">RBAC & Users</h2></div>
        <div class="rank-list" id="usersList"></div>
    </section>
</div>
"""

# Substituir o conteúdo entre o banner e o fim do main
main_content_pattern = re.escape(body_start_marker) + r'.*?' + re.escape(body_end_marker)
content = re.sub(main_content_pattern, body_start_marker + "\n" + new_masonry_body + "\n" + body_end_marker, content, flags=re.DOTALL)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("True Masonry Layout (Column-based) implementado.")
