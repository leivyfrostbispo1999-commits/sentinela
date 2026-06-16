import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. CSS Brutal: Destruir qualquer Grid/Flex residual e implementar True Masonry
brutal_css = """
    /* TRUE CSS MASONRY - ZERO ESPAÇOS MORTOS */
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
        
        border: 1px solid var(--border-subtle);
        border-radius: 2px;
        background: var(--surface-primary);
        
        flex: unset !important;
        grid-row: unset !important;
        align-self: start !important;
        contain: layout paint;
    }

    /* Otimização de Performance */
    .feed, .timeline-compact, .rank-list {
        transform: translateZ(0);
        will-change: transform;
    }
"""

# Limpar todo o bloco de style e injetar o novo
content = re.sub(r'/\* TRUE MASONRY PACKING ARCHITECTURE \*/.*?</style>', brutal_css + "\n</style>", content, flags=re.DOTALL)

# 2. HTML Brutal: Remover wrappers e transformar tudo em .widget-card
# Localizar o início do banner e o fim do main
body_start_marker = '<div class="critical-banner" id="criticalBanner">INCIDENTE CRÍTICO EM ANDAMENTO</div>'
body_end_marker = '</main>'

new_radical_masonry = """<div class="masonry-root" id="dashboard-masonry">
    <!-- WIDGETS FILHOS DIRETOS -->
    
    <section class="widget-card" id="incidentsListPanel">
        <div class="panel-head"><h2 class="panel-title">Fila de Incidentes</h2><div class="live" id="incidentsStatus">...</div></div>
        <div class="toolbar" style="padding: 4px; border-bottom: 1px solid var(--border-subtle);">
            <select class="select" id="incidentStatusFilter" style="flex:1;"><option value="all">Status</option></select>
        </div>
        <div class="rank-list" id="incidentsList"></div>
    </section>

    <section class="widget-card" id="incidentPanel">
        <div class="panel-head"><h2 class="panel-title">Workspace Investigativo</h2><div class="live">LIVE</div></div>
        <div class="incident-overview" id="attackChainWrapper" style="padding:8px;">
            <div style="display:flex; justify-content:space-between; margin-bottom:4px;">
                <span class="rail-label">Atacante:</span>
                <strong id="attackerIp">--</strong>
            </div>
            <div class="mitre-flow" id="attackChains"></div>
        </div>
        <div class="timeline-compact" id="enterpriseTimeline"></div>
    </section>

    <section class="widget-card" id="ai-xdr-section">
        <div class="panel-head"><h2 class="panel-title">AI & SOAR Intelligence</h2></div>
        <div id="ai-scores-list" class="rank-list"></div>
        <div id="soar-status" class="rank-list"></div>
    </section>

    <section class="widget-card" id="feedPanel">
        <div class="panel-head"><h2 class="panel-title">Operational Alert Stream</h2></div>
        <div class="feed">
            <table>
                <thead><tr><th>TIME</th><th>SOURCE &rarr; TARGET</th><th>SEV</th><th>RISK</th><th>MITRE</th><th>ACTION</th></tr></thead>
                <tbody id="feedBody"></tbody>
            </table>
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
        </div>
    </section>

    <section class="widget-card" id="adminUsersPanel">
        <div class="panel-head"><h2 class="panel-title">RBAC & Users</h2></div>
        <div class="rank-list" id="usersList"></div>
    </section>
</div>
"""

# Injetar o novo corpo
content = re.sub(re.escape(body_start_marker) + r'.*?' + re.escape(body_end_marker), body_start_marker + "\n" + new_radical_masonry + "\n" + body_end_marker, content, flags=re.DOTALL)

# 3. Lógica JS: Ocultar Cadeia de Ataque se vazia
logic_addition = """
        // Lógica de visibilidade automática para Cadeia de Ataque
        function updateAttackChainVisibility() {
            const chain = el('attackChains');
            const wrapper = el('attackChainWrapper');
            if (chain && wrapper) {
                const hasContent = chain.innerHTML.trim() !== "" && !chain.innerHTML.includes("empty-state");
                wrapper.style.display = hasContent ? "block" : "none";
            }
        }
        
        // Chamar updateAttackChainVisibility sempre que refreshCorrelation rodar
        const originalRefreshCorrelation = refreshCorrelation;
        refreshCorrelation = async function() {
            await originalRefreshCorrelation();
            updateAttackChainVisibility();
        };
"""

content = content.replace("connectSocketIO();", logic_addition + "\n        connectSocketIO();")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Estrutura destruída e True Masonry reconstruído com sucesso.")
