import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. CSS CIRÚRGICO - REMOVER ALTURAS FORÇADAS E IMPLEMENTAR CLASSES ESPECÍFICAS
# Vou substituir o bloco de "Reset total para os culpados" pelo solicitado
requested_css = """
    /* ZERO ALTURA FANTASMA - FIX RESIDUAL */
    .attack-chain-panel,
    .replay-panel,
    #attackChainWrapper,
    #replayPanel,
    #attack-chain,
    #replay-retention,
    #incidentPanel,
    #iocPanel {
        height: auto !important;
        min-height: 0 !important;
        max-height: none !important;

        flex: unset !important;
        flex-grow: 0 !important;

        display: inline-block !important;
        width: 100% !important;
    }
"""

content = re.sub(r'/\* Reset total para os culpados.*?\s+width: 100%;\s+\}', requested_css, content, flags=re.DOTALL)

# 2. JS CIRÚRGICO - OCULTAÇÃO AGRESSIVA (children.length)
# Vou atualizar a função enforceAbsoluteMasonryPacking
new_js_logic = """
        // Ocultação Absoluta se vazio (Zero pixels e Zero vácuo)
        function enforceAbsoluteMasonryPacking() {
            const targets = [
                { contentId: 'attackChains', wrapId: 'attackChainWrapper' },
                { contentId: 'replayResults', wrapId: 'replayPanel' },
                { contentId: 'iocResults', wrapId: 'iocPanel' },
                { contentId: 'ai-scores-list', wrapId: 'aiIntelligencePanel' },
                { contentId: 'soar-status', wrapId: 'soarPanel' }
            ];
            
            targets.forEach(t => {
                const contentEl = el(t.contentId);
                const wrapperEl = el(t.wrapId);
                if (contentEl && wrapperEl) {
                    // Check if has children and isn't just empty text or placeholder
                    const hasChildren = contentEl.children.length > 0;
                    const hasRealText = contentEl.innerText.trim().length > 10; // Avoid "Aguardando..."
                    const isVisible = hasChildren || hasRealText;
                    
                    if (!isVisible) {
                        wrapperEl.style.setProperty('display', 'none', 'important');
                    } else {
                        wrapperEl.style.setProperty('display', 'inline-block', 'important');
                    }
                }
            });
        }
"""

content = re.sub(r'function enforceAbsoluteMasonryPacking\(\) \{.*?\}', new_js_logic, content, flags=re.DOTALL)

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Correção de alturas residuais e ocultação agressiva aplicada.")
