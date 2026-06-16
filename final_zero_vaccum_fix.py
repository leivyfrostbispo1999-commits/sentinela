import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. CSS CIRÚRGICO - REMOVER ALTURAS FORÇADAS DOS IDS ESPECÍFICOS
radical_css_fix = """
    /* ZERO ALTURA FANTASMA - FIX DEFINITIVO */
    .dashboard-masonry {
        column-count: 2;
        column-gap: 16px;
        padding: 16px;
        display: block !important;
        width: 100%;
        box-sizing: border-box;
    }

    @media (max-width: 1400px) {
        .dashboard-masonry { column-count: 1; }
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

    /* Reset total para os culpados das áreas mortas */
    #attackChainWrapper, 
    #replayPanel, 
    #iocPanel, 
    #incidentPanel,
    #aiIntelligencePanel,
    #soarPanel {
        height: auto !important;
        min-height: 0 !important;
        max-height: none !important;
        flex: unset !important;
        flex-grow: 0 !important;
        display: inline-block !important;
        width: 100%;
    }

    .feed-container, .timeline-container, .rank-list {
        max-height: 500px;
        overflow-y: auto;
        height: auto !important;
        min-height: 0 !important;
    }
"""

# Limpar e injetar o CSS radical
content = re.sub(r'<style>.*?</style>', "<style>\n" + radical_css_fix + "\n</style>", content, flags=re.DOTALL)

# 2. JS CIRÚRGICO - HIDE SE VAZIO (DISPLAY:NONE)
# Vou limpar a lógica duplicada anterior e injetar a definitiva
js_hide_logic = """
        // True Masonry: Ocultação absoluta se vazio (zero pixels)
        function enforceAbsoluteMasonryPacking() {
            const rules = [
                { id: 'attackChains', wrapId: 'attackChainWrapper' },
                { id: 'replayResults', wrapId: 'replayPanel' },
                { id: 'iocResults', wrapId: 'iocPanel' },
                { id: 'ai-scores-list', wrapId: 'aiIntelligencePanel' },
                { id: 'soar-status', wrapId: 'soarPanel' }
            ];
            
            rules.forEach(r => {
                const content = el(r.id);
                const wrapper = el(r.wrapId);
                if (content && wrapper) {
                    const hasData = content.innerHTML.trim() !== "" && 
                                  !content.innerHTML.includes("empty-state") &&
                                  !content.innerHTML.includes("Aguardando");
                    
                    // Se não tiver filhos reais ou for placeholder, desaparece do layout
                    if (!hasData || content.children.length === 0) {
                        wrapper.style.setProperty('display', 'none', 'important');
                    } else {
                        wrapper.style.setProperty('display', 'inline-block', 'important');
                    }
                }
            });
        }
        
        // Hooks de Refresh
        const _refreshInc = refreshIncidents;
        refreshIncidents = async function() { await _refreshInc(); enforceAbsoluteMasonryPacking(); };
        
        const _refreshCorr = refreshCorrelation;
        refreshCorrelation = async function() { await _refreshCorr(); enforceAbsoluteMasonryPacking(); };
"""

# Remover tentativas anteriores de lógica e injetar a nova
content = re.sub(r'// Lógica de visibilidade automática.*?connectSocketIO\(\);', js_hide_logic + "\n        connectSocketIO();", content, flags=re.DOTALL)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Widgets específicos limpos e ocultação dinâmica implementada.")
