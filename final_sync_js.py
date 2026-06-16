import re

file_path = r"D:\sentinela\services\dashboard_web\index.html"
with open(file_path, "r", encoding="utf-8") as f:
    content = f.read()

# 1. Ajustar JS para apontar para dashboard-masonry em vez de productConsole
content = content.replace("el('productConsole').scrollIntoView", "el('dashboard-masonry').scrollIntoView")

# 2. Adicionar o ID dashboard-masonry se ele foi trocado ou garantir que existe
# No refactor_true_masonry.py eu usei <div class="dashboard-masonry">, vou adicionar o ID
content = content.replace('<div class="dashboard-masonry">', '<div class="dashboard-masonry" id="dashboard-masonry">')

# 3. Corrigir referências a productConsole no loop de classes essenciais
content = content.replace("'productConsole',", "'dashboard-masonry',")

# 4. Remover o botão "OUT" que ficou redundante (eu adicionei logoutButton no header)
# Na verdade, no fix_header_nav.py eu adicionei o logoutButton como "OUT"
# Vou deixar como está, ou mudar para "LOGOUT" se preferir. "OUT" é bem técnico/compacto.

with open(file_path, "w", encoding="utf-8") as f:
    f.write(content)

print("JS e IDs sincronizados com o novo layout.")
