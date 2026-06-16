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
    }

    .panel, .card, .widget-card {
        display: inline-block;
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
    
    .feed { max-height: 450px; overflow: auto; }
    .timeline-compact { max-height: 500px; overflow-y: auto; }
    #incidentsList { max-height: 250px; overflow-y: auto; }
"""

content = re.sub(r'/\* TRUE MASONRY PACKING ARCHITECTURE \*/.*?\n\s+ #incidentsList \{ max-height: 250px; overflow-y: auto; \}', masonry_css, content, flags=re.DOTALL)

# 2. Restaurar Header completo e IDs de Navegação
new_header = """<header>
    <div class="header-top">
        <section class="brand-panel">
            <h1>SENTINELA SOC</h1>
        </section>
        <aside class="header-status">
            <div class="toolbar">
                <button class="button focus-toggle" id="focusModeButton">FOCUS</button>
                <select class="select" id="rangeSelect">
                    <option value="5m">5m</option>
                    <option value="1h" selected>1h</option>
                    <option value="24h">24h</option>
                </select>
                <div class="mode-toggle">
                    <button class="mode-button active" id="demoModeButton">DEMO</button>
                    <button class="mode-button" id="historyModeButton">HIST</button>
                    <button class="mode-button" id="huntingModeButton">HUNT</button>
                    <button class="mode-button" id="rulesModeButton">REGRAS</button>
                </div>
                <button class="button demo" id="simulateAttackButton">SIMULAR</button>
                <button class="button" id="refreshButton">SYNC</button>
            </div>
            <div class="session-line">
                <strong id="apiStatus" class="status-pill degraded">API</strong>
                <strong id="wsStatus" class="status-pill degraded">WS</strong>
            </div>
            <form class="login-bar" id="loginForm">
                <input class="login-input" id="usernameInput" value="admin" style="width:60px;">
                <input class="login-input" id="passwordInput" type="password" placeholder="senha" style="width:60px;">
                <button class="button" id="loginButton">OK</button>
                <button class="button" id="logoutButton" type="button">OUT</button>
            </form>
        </aside>
    </div>
    <div class="command-rail">
        <div class="rail-item"><span class="rail-label">Threat:</span><span class="level low" id="threatLevel">LOW</span></div>
        <div class="rail-item"><span class="rail-label">Incid:</span><span class="rail-value" id="totalEventos">0</span></div>
        <div class="rail-item"><span class="rail-label">Crit:</span><span class="rail-value" id="eventosCriticos" style="color:var(--red)">0</span></div>
        <div class="rail-item"><span class="rail-label">IPs:</span><span class="rail-value" id="ipsUnicos">0</span></div>
        <div class="rail-item"><span class="rail-label">Risk:</span><span class="rail-value" id="bloqueios">0</span></div>
        <div class="rail-item"><span class="rail-label">MITRE:</span><span class="rail-value" id="tiMatches">N/D</span></div>
        <div class="rail-item"><span class="rail-label">RAM:</span><span class="rail-value" id="opsMemoryValue">--</span></div>
        <div class="rail-item"><span class="rail-label">CPU:</span><span class="rail-value" id="opsUptimeValue">--</span></div>
        <div style="flex:1;"></div>
        <input class="search" id="searchInput" placeholder="Filtro rápido..." style="width:180px;">
        <select class="select" id="severityFilter" style="margin-left:4px;">
            <option value="all">Todas</option>
            <option value="critical">Crit</option>
            <option value="high">Alt</option>
        </select>
    </div>
</header>"""

content = re.sub(r'<header>.*?</header>', new_header, content, flags=re.DOTALL)

# 3. Assegurar IDs para Navegação no dashboard-masonry
# Vou envolver o Rule Studio e o Hunting com IDs específicos se necessário
# mas eles já possuem ids="ruleStudio" e id="huntingConsole"

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Header e navegação restaurados.")
