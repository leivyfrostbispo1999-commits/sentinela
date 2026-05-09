import re
import json

class SigmaRuleCompiler:
    """
    Compilador de regras estilo Sigma para o SENTINELA.
    Suporta:
    - Modificadores (contains, startswith, endswith, re)
    - Condições booleanas (and, or, not)
    - Agregações (1 of selection*, all of selection*)
    """
    
    def __init__(self, rule_dict):
        self.rule = rule_dict
        self.title = rule_dict.get("title", "unnamed")
        self.detection = rule_dict.get("detection", {})
        self.condition_str = self.detection.get("condition", "")
        self.selections = {k: v for k, v in self.detection.items() if k != "condition"}

    def _match_value(self, log_value, condition_value, modifier=None):
        if log_value is None:
            return False
        
        log_str = str(log_value).lower()
        
        # Se for lista, qualquer um (OR)
        if isinstance(condition_value, list):
            return any(self._match_value(log_value, v, modifier) for v in condition_value)
        
        cond_str = str(condition_value).lower()
        
        if modifier == "contains":
            return cond_str in log_str
        if modifier == "startswith":
            return log_str.startswith(cond_str)
        if modifier == "endswith":
            return log_str.endswith(cond_str)
        if modifier == "re":
            try:
                return bool(re.search(condition_value, str(log_value), re.IGNORECASE))
            except Exception:
                return False
        
        # Default: Exact Match
        return log_str == cond_str

    def _evaluate_selection(self, log, selection_name):
        selection = self.selections.get(selection_name)
        if not selection:
            return False
        
        # Sigma Selections dentro de um dicionário são AND implícito
        for field_expr, value in selection.items():
            if "|" in field_expr:
                field, modifier = field_expr.split("|", 1)
            else:
                field, modifier = field_expr, None
            
            log_value = log.get(field)
            if not self._match_value(log_value, value, modifier):
                return False
        return True

    def match(self, log):
        """Avalia o log atual contra a condição da regra."""
        if not self.condition_str:
            # Fallback: Se houver apenas uma seleção, ela é o resultado
            if len(self.selections) == 1:
                return self._evaluate_selection(log, list(self.selections.keys())[0])
            # Se houver várias e nenhuma condição, assume OR (Sigma spec costuma exigir condition se > 1)
            return any(self._evaluate_selection(log, s) for s in self.selections)

        # Tokenização simples e avaliação booleana segura
        # NOTA: Para produção, usaríamos um parser formal (PLY/Lark), mas aqui
        # traduziremos para Python e usaremos eval sanitizado para velocidade de impl.
        
        expr = self.condition_str.lower()
        
        # 1. Resolve agregações: "1 of selection*" ou "all of selection*"
        if "1 of " in expr:
            pattern = expr.split("1 of ")[1].strip().replace("*", ".*")
            matches = [s for s in self.selections.keys() if re.match(pattern, s)]
            val = any(self._evaluate_selection(log, m) for m in matches)
            return val
        
        if "all of " in expr:
            pattern = expr.split("all of ")[1].strip().replace("*", ".*")
            matches = [s for s in self.selections.keys() if re.match(pattern, s)]
            val = all(self._evaluate_selection(log, m) for m in matches)
            return val

        # 2. Mapeia seleções nomeadas para booleanos
        eval_context = {}
        for sel_name in self.selections.keys():
            eval_context[sel_name.lower()] = self._evaluate_selection(log, sel_name)
        
        # 3. Traduz sintaxe Sigma para Python
        python_expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace("not ", "not ")
        
        try:
            # Avalia a expressão no contexto das seleções
            return eval(python_expr, {"__builtins__": {}}, eval_context)
        except Exception as e:
            # Fallback seguro
            return False
