"""
Módulo de Detección de Vulnerabilidades SQL Injection
Implementa criterios formales OWASP para detección SQLi.

Este módulo contiene la lógica de análisis y detección de vulnerabilidades
SQL Injection basada en múltiples técnicas: error-based, time-based,
boolean-blind, length-based y análisis de cambios HTML.
"""

import re
import time
from typing import Dict, List, Optional, Tuple
import difflib

class SQLInjectionDetector:
    """
    Detector de vulnerabilidades SQL Injection basado en criterios OWASP.
    
    Esta clase implementa múltiples técnicas de detección SQL Injection:
    error-based (detección de errores SQL), time-based (retrasos en respuesta),
    boolean-blind (diferencias entre respuestas TRUE y FALSE), length-based
    (diferencias de longitud) y análisis de cambios HTML/DOM.
    """
    
    SQL_ERROR_PATTERNS = [
        r"syntax error", r"SQLSTATE", r'near "', r"unclosed quotation mark",
        r"You have an error in your SQL syntax", r"OperationalError", r"SQLiteException",
        r"MySQLSyntaxErrorException", r"PostgreSQL.*ERROR", r"Warning.*\Wmysql_",
        r"valid MySQL result", r"MySqlClient\.", r"PostgreSQL query failed",
        r"Warning.*\Wpg_", r"Warning.*\Woci_", r"Warning.*\Wodbc_",
        r"Warning.*\Wmssql_", r"Warning.*\Wsqlsrv_", r"Warning.*\Wfbsql_",
        r"Warning.*\Wibase_", r"Warning.*\Wifx_", r"Exception.*\Worg\.hibernate",
        r"Exception.*\Worg\.springframework", r"java\.sql\.SQLException",
        r"java\.sql\.SQLSyntaxErrorException", r"com\.mysql\.jdbc\.exceptions",
        r"com\.microsoft\.sqlserver\.jdbc", r"org\.postgresql\.util\.PSQLException",
        r"org\.h2\.jdbc\.JdbcSQLException", r"SQLException", r"SQLSyntaxErrorException",
        r"ORA-\d{5}", r"PLS-\d{5}", r"SQL error", r"SQL.*error", r"SQL.*Exception",
        r"Query failed", r"SQL command not properly ended", r"quoted string not properly terminated",
        r"invalid character", r"invalid number", r"column.*does not exist",
        r"table.*does not exist", r"unknown column", r"unknown table",
        r"table.*already exists", r"column.*already exists"
    ]
    
    TIME_BASED_THRESHOLD = 5.0
    
    def __init__(self):
        """
        Inicializa el detector de vulnerabilidades SQL Injection.
        
        Compila todos los patrones regex de errores SQL en objetos regex
        reutilizables para búsquedas eficientes en las respuestas.
        """
        self.error_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_ERROR_PATTERNS]
    
    def detect_sql_errors(self, response_text: str) -> List[Dict]:
        """
        Detecta errores SQL en el texto de respuesta y extrae el contexto.
        
        Busca patrones de errores SQL en el texto de respuesta usando expresiones
        regulares. Para cada error encontrado, extrae un snippet con contexto
        (100 caracteres antes y después) para incluirlo en el reporte.
        
        Args:
            response_text (str): Texto de la respuesta HTTP a analizar
            
        Returns:
            List[Dict]: Lista de diccionarios, cada uno con:
                - 'pattern': Patrón regex que coincidió
                - 'snippet': Fragmento de texto con el error y su contexto
        """
        found_errors = []
        for pattern in self.error_patterns:
            match = pattern.search(response_text)
            if match:
                start = max(0, match.start() - 100)
                end = min(len(response_text), match.end() + 100)
                snippet = response_text[start:end]
                snippet = " ".join(snippet.split())
                
                found_errors.append({
                    'pattern': pattern.pattern,
                    'snippet': snippet
                })
        return found_errors
    
    def detect_time_based_sqli(self, response_time: float, payload_type: str) -> bool:
        """
        Detecta vulnerabilidades SQL Injection basadas en tiempo (time-based).
        
        Verifica si la respuesta tardó más de un umbral determinado, lo cual
        indica que el payload causó un retraso intencional (ej: SLEEP, WAITFOR DELAY).
        
        Args:
            response_time (float): Tiempo de respuesta en segundos
            payload_type (str): Tipo de payload utilizado (debe ser 'time_based')
            
        Returns:
            bool: True si se detecta una vulnerabilidad time-based, False en caso contrario
        """
        if payload_type != 'time_based':
            return False
        return response_time >= self.TIME_BASED_THRESHOLD
    
    def analyze_html_changes(self, base_response: str, test_response: str) -> Dict:
        """
        Analiza cambios en el HTML entre la respuesta base y la respuesta con payload.
        
        Compara dos respuestas HTML usando SequenceMatcher para calcular la similitud
        y detectar cambios significativos. Utiliza umbrales anti-ruido para ignorar
        cambios menores como timestamps o tokens temporales.
        
        Args:
            base_response (str): Texto HTML de la respuesta base (sin payload)
            test_response (str): Texto HTML de la respuesta con payload inyectado
            
        Returns:
            Dict: Diccionario con:
                - 'similarity': Ratio de similitud entre 0.0 y 1.0
                - 'length_diff': Diferencia absoluta de longitud en bytes
                - 'significant_change': True si el cambio es significativo
                - 'dom_changes': Lista de cambios DOM (actualmente siempre vacía)
        """
        if not base_response or not test_response:
            return {
                'similarity': 0.0, 'length_diff': abs(len(test_response) - len(base_response)),
                'significant_change': False, 'dom_changes': []
            }
        
        similarity = difflib.SequenceMatcher(None, base_response, test_response).ratio()
        length_diff = abs(len(test_response) - len(base_response))
        
        significant_change = similarity < 0.95 and length_diff > 50
        
        return {
            'similarity': similarity,
            'length_diff': length_diff,
            'significant_change': significant_change
        }
    
    def detect_boolean_blind_sqli(self, base_response: str, true_response: str, false_response: str) -> bool:
        """
        Detecta vulnerabilidades SQL Injection boolean-blind.
        
        Compara las respuestas obtenidas con condiciones TRUE y FALSE. Si las
        respuestas son significativamente diferentes, indica una vulnerabilidad
        boolean-blind donde el servidor responde diferente según condiciones SQL.
        
        Args:
            base_response (str): Texto de la respuesta base (sin payload)
            true_response (str): Texto de la respuesta con condición TRUE
            false_response (str): Texto de la respuesta con condición FALSE
            
        Returns:
            bool: True si se detecta una vulnerabilidad boolean-blind, False en caso contrario
        """
        if not base_response or not true_response or not false_response:
            return False
            
        true_false_similarity = difflib.SequenceMatcher(None, true_response, false_response).ratio()
        
        if true_false_similarity < 0.9:
            return True
        return False
    
    def detect_length_based_sqli(self, base_length: int, test_length: int, threshold: float = 0.15) -> bool:
        """
        Detecta vulnerabilidades SQL Injection basadas en diferencias de longitud.
        
        Compara la longitud de la respuesta base con la respuesta con payload.
        Considera una diferencia significativa si cumple un ratio mínimo y una
        diferencia absoluta mínima para evitar falsos positivos.
        
        Args:
            base_length (int): Longitud en bytes de la respuesta base
            test_length (int): Longitud en bytes de la respuesta con payload
            threshold (float): Ratio mínimo de diferencia (default: 0.15 = 15%)
            
        Returns:
            bool: True si se detecta una diferencia significativa, False en caso contrario
        """
        if base_length == 0: return False
        
        diff = abs(test_length - base_length)
        diff_ratio = diff / base_length
        
        if diff_ratio >= threshold and diff > 50:
            return True
        return False

    def evaluate_payload(self, payload_info: Dict, base_response: Dict, test_response: Dict) -> Dict:
        """
        Evalúa un payload completo utilizando todas las técnicas de detección.
        
        Analiza la respuesta del servidor con el payload inyectado usando múltiples
        técnicas de detección en orden de prioridad: error-based, time-based,
        boolean-blind, length-based, cambios de código de estado, y extracción
        de queries SQL filtradas. Genera un resultado detallado con evidencia
        y niveles de confianza.
        
        Args:
            payload_info (Dict): Diccionario con información del payload que contiene:
                - 'payload': Cadena con el payload SQL inyectado
                - 'type': Tipo de payload (basic, union, boolean_blind, time_based, error_based)
            base_response (Dict): Diccionario con la respuesta base que contiene:
                - 'text': Texto de la respuesta HTTP
                - 'status_code': Código de estado HTTP
                - 'length': Longitud de la respuesta
            test_response (Dict): Diccionario con la respuesta con payload que contiene:
                - 'text': Texto de la respuesta HTTP
                - 'status_code': Código de estado HTTP
                - 'time': Tiempo de respuesta en segundos
                - 'is_boolean_test': True si es una prueba boolean (opcional)
                
        Returns:
            Dict: Diccionario con el resultado del análisis que contiene:
                - 'payload': Payload utilizado
                - 'payload_type': Tipo de payload
                - 'vulnerable': True si se detecta vulnerabilidad, False en caso contrario
                - 'vulnerability_type': Tipo de vulnerabilidad detectada
                - 'confidence': Nivel de confianza ('high', 'medium', 'low')
                - 'evidence': Lista de cadenas con evidencia encontrada
                - 'indicators': Diccionario con indicadores adicionales
                - 'status_code', 'response_time', 'response_length', 'base_length': Métricas
        """
        payload = payload_info['payload']
        payload_type = payload_info['type']
        
        test_text = test_response.get('text', '')
        test_time = test_response.get('time', 0.0)
        test_status = test_response.get('status_code', 0)
        test_length = len(test_text)
        
        base_text = base_response.get('text', '')
        base_length = len(base_text)
        base_status = base_response.get('status_code', 200)
        
        result = {
            'payload': payload, 'payload_type': payload_type,
            'status_code': test_status, 'response_time': test_time,
            'response_length': test_length, 'base_length': base_length,
            'vulnerable': False, 'vulnerability_type': None,
            'confidence': 'low', 'evidence': [], 'indicators': {}
        }
        
        sql_errors = self.detect_sql_errors(test_text)
        if sql_errors:
            result['vulnerable'] = True
            result['vulnerability_type'] = 'error_based'
            result['confidence'] = 'high'
            patterns_found = [e['pattern'] for e in sql_errors]
            result['evidence'].append(f"SQL errors detected: {', '.join(patterns_found[:3])}")
            
            result['indicators']['error_snippet'] = sql_errors[0]['snippet']
            result['indicators']['response_preview'] = sql_errors[0]['snippet'] 
        
        if self.detect_time_based_sqli(test_time, payload_type):
            result['vulnerable'] = True
            result['vulnerability_type'] = 'time_based'
            result['confidence'] = 'high'
            result['evidence'].append(f"Time-based delay detected: {test_time:.2f}s")
        
        html_analysis = self.analyze_html_changes(base_text, test_text)
        result['indicators']['html_analysis'] = html_analysis
        
        if not result['vulnerable'] and (payload_type == 'boolean_blind' or test_response.get('is_boolean_test')):
             if html_analysis['similarity'] < 0.90: 
                result['vulnerable'] = True
                result['vulnerability_type'] = 'boolean_blind'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Significant structure change (similarity: {html_analysis['similarity']:.2f})")

        if self.detect_length_based_sqli(base_length, test_length, threshold=0.15):
             if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Significant length difference ({abs(test_length - base_length)} bytes)")

        if test_status != base_status and test_status < 500: 
             if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'basic'
                result['confidence'] = 'medium'
                result['evidence'].append(f"Status code changed: {base_status} -> {test_status}")

        filtered_query = self._extract_filtered_query(test_text)
        if filtered_query:
            result['indicators']['filtered_query'] = filtered_query
            if not result['vulnerable']:
                result['vulnerable'] = True
                result['vulnerability_type'] = 'error_based'
                result['confidence'] = 'high'
            result['evidence'].append("SQL query leaked in response")
            result['indicators']['response_preview'] = filtered_query

        if result['vulnerable'] and 'response_preview' not in result['indicators']:
            preview = self._get_smart_preview(base_text, test_text)
            preview = preview.replace('<', '&lt;').replace('>', '&gt;')
            result['indicators']['response_preview'] = preview

        return result
    
    def _extract_filtered_query(self, response_text: str) -> Optional[str]:
        """
        Extrae queries SQL filtradas que aparecen en la respuesta HTTP.
        
        Busca patrones de queries SQL (SELECT, INSERT, UPDATE) en el texto de
        respuesta, lo que indica que la aplicación filtró información SQL.
        
        Args:
            response_text (str): Texto de la respuesta HTTP a analizar
            
        Returns:
            Optional[str]: Fragmento de texto con la query SQL encontrada,
                o None si no se encuentra ninguna query
        """
        patterns = [
            r"(SELECT[\s\S]{0,800}FROM[\s\S]{0,800}WHERE[\s\S]{0,800})",
            r"(INSERT[\s\S]{0,800}INTO[\s\S]{0,800}VALUES[\s\S]{0,800})",
            r"(UPDATE[\s\S]{0,800}SET[\s\S]{0,800}WHERE[\s\S]{0,800})",
        ]

        for pattern in patterns:
            match = re.search(pattern, response_text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(0)[:800]

        return None

    def get_vulnerability_description(self, vuln_type: str) -> str:
        """
        Obtiene una descripción legible de un tipo de vulnerabilidad SQL Injection.
        
        Args:
            vuln_type (str): Tipo de vulnerabilidad (error_based, time_based, boolean_blind, union, basic)
            
        Returns:
            str: Descripción en español del tipo de vulnerabilidad
        """
        descriptions = {
            'error_based': 'Error-based SQL Injection: El servidor revela información de error SQL',
            'time_based': 'Time-based Blind SQL Injection: El servidor responde con retrasos controlados',
            'boolean_blind': 'Boolean-based Blind SQL Injection: El servidor responde diferente según condiciones booleanas',
            'union': 'UNION-based SQL Injection: Permite extraer datos mediante UNION SELECT',
            'basic': 'Basic SQL Injection: Inyección SQL básica que altera la lógica de la consulta'
        }
        return descriptions.get(vuln_type, 'Unknown SQL Injection type')

    def _get_smart_preview(self, base_text: str, test_text: str, window: int = 200) -> str:
        """
        Genera un preview inteligente mostrando la zona donde cambia el HTML.
        
        Encuentra el primer punto donde las dos respuestas difieren y extrae
        un fragmento de texto alrededor de ese punto para mostrar en el reporte.
        Esto ayuda a identificar rápidamente qué parte de la respuesta cambió.
        
        Args:
            base_text (str): Texto de la respuesta base
            test_text (str): Texto de la respuesta con payload
            window (int): Número de caracteres a incluir antes y después
                del punto de diferencia (default: 200)
                
        Returns:
            str: Fragmento de texto con el contexto alrededor de la diferencia,
                con prefijo y sufijo "..." si el texto está recortado
        """
        if not base_text or not test_text:
            return test_text[:300]

        limit = min(len(base_text), len(test_text))
        diff_index = -1
        
        for i in range(limit):
            if base_text[i] != test_text[i]:
                diff_index = i
                break
        
        if diff_index == -1:
            if len(test_text) != len(base_text):
                diff_index = limit
            else:
                return test_text[:300]

        start = max(0, diff_index - window)
        end = min(len(test_text), diff_index + window)
        
        preview = test_text[start:end]
        
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(test_text) else ""
        
        return f"{prefix}{preview}{suffix}"