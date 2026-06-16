import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Ajustar o Grid Principal e a área de investigação para ALIGN-ITEMS: START
# Remover qualquer herança de stretch
content = content.replace(
    ".grid { \n    display: grid; \n    grid-template-columns: repeat(12, minmax(0, 1fr)); \n    gap: var(--space-2); \n}",
    ".grid { \n    display: grid; \n    grid-template-columns: repeat(12, minmax(0, 1fr)); \n    gap: var(--space-2); \n    align-items: start; \n    grid-auto-rows: auto; \n}"
)

content = content.replace(
    ".investigation-workspace {\n    display: grid;\n    grid-template-columns: repeat(12, 1fr);\n    gap: var(--space-2);\n    grid-column: span 12;\n}",
    ".investigation-workspace {\n    display: grid;\n    grid-template-columns: repeat(12, 1fr);\n    gap: var(--space-2);\n    grid-column: span 12;\n    align-items: start;\n    grid-auto-rows: auto;\n}"
)

# 2. Aplicar ALIGN-ITEMS: START em wrappers de coluna para evitar que sub-painéis estiquem
content = content.replace(
    "display: flex; flex-direction: column; gap: var(--space-2);",
    "display: flex; flex-direction: column; gap: var(--space-2); align-items: stretch;" # Flex column ainda precisa esticar largura, mas altura é controlada pelo conteúdo
)

# 3. Remover explicitamente alturas fixas ou 100% de painéis
content = content.replace("height: auto;", "height: fit-content;")

# 4. Reduzir min-heights residuais (se houver) e garantir que Rule Studio e outros não forcem altura
# O editor Monaco tem altura fixa no JS/CSS, vamos garantir que o container dele não estique o vizinho.

# 5. Ajustar o CSS para garantir que cada coluna lateral não estique a outra
css_masonry_addition = """
/* CORREÇÃO MASONRY: INDEPENDÊNCIA DE ALTURA */
.workspace-left, .workspace-center, .workspace-right, .analytics-column, .map-column {
    align-self: start;
    height: fit-content;
}

.panel, .card {
    align-self: start;
    width: 100%; /* Garante preenchimento horizontal */
}

/* Timeline e Feed podem crescer conforme conteúdo, mas sem forçar os vizinhos */
#enterpriseTimeline, .feed {
    height: auto;
    max-height: 600px;
}

#monacoEditor {
    min-height: 250px;
}
"""

# Inserir antes do fechamento do style
content = content.replace("</style>", css_masonry_addition + "\n</style>")

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("Layout Masonry (Independent Height) implementado.")
