#!/usr/bin/env python3
"""
SQL Injection Scanner - Herramienta Profesional de Detección
Punto de entrada principal de la aplicación.
Este módulo orquesta todo el proceso de escaneo: parseo de argumentos,
inicialización de componentes, ejecución del escaneo y generación de reportes.
"""

import sys
import os
from typing import Dict, List, Optional

from cli import parse_arguments, validate_url, parse_json_input, get_payloads_by_mode, print_banner, print_summary
from scanner import SQLInjectionScanner
from sqli_detector import SQLInjectionDetector
from ml_classifier import SQLInjectionMLClassifier
from reporter import ReportGenerator

def main():
    """
    Función principal del programa.
    
    Orquesta todo el proceso de escaneo SQL Injection:
    1. Parseo y validación de argumentos de línea de comandos
    2. Inicialización de componentes (scanner, detector, clasificador ML)
    3. Verificación de conectividad con el servidor objetivo
    4. Ejecución del escaneo sobre los endpoints especificados
    5. Análisis de resultados y detección de vulnerabilidades
    6. Generación de reportes en diferentes formatos (consola, HTML, JSON)
    7. Manejo de errores y excepciones
    
    Exits:
        sys.exit(0): Si no se encuentran vulnerabilidades
        sys.exit(1): Si se encuentran vulnerabilidades o hay un error
        sys.exit(130): Si el usuario interrumpe con Ctrl+C
    """
    try:
        print_banner()
        
        args = parse_arguments()
        
        if not validate_url(args.url):
            print("[!] Error: URL inválida")
            sys.exit(1)
        
        timeout = args.timeout
        if args.aggressive:
            timeout = timeout * 2
        
        cookies = parse_json_input(args.cookies) if args.cookies else {}
        headers = parse_json_input(args.headers) if args.headers else {}
        if args.forced_params is not None:
            forcedParameters= args.forced_params.split(",")
        else:
            forcedParameters= []
        if args.forced_values is not None:
            forcedValues= args.forced_values.split(",")
        else:
            forcedValues=[]

        if not isinstance(forcedParameters, list) or not isinstance(forcedValues, list):
            print("[!] Error: se esperaban arrays (listas) para argumentos y valores forzados")
            sys.exit(1)
        
        if len(forcedParameters) != len(forcedValues):
            print("[!] Error: argumentos y parámetros forzados tienen longitudes incompatibles")
            sys.exit(1)
        
        payloads = get_payloads_by_mode(args.attack, args.payload_set)
        print(f"[*] Loaded {len(payloads)} payloads")
        
        scanner = SQLInjectionScanner(
            timeout=timeout,
            cookies=cookies,
            headers=headers,
            verify_ssl=args.verify_ssl
        )
        
        print("[*] Checking server connectivity...")
        if not scanner.check_connectivity(args.url):
            print(f"[!] ERROR: Cannot connect to {args.url}")
            print(f"[!] Please ensure the server is running and accessible")
            print(f"[!] Common issues:")
            print(f"    - Server is not running")
            print(f"    - Wrong URL or port")
            print(f"    - Firewall blocking connection")
            sys.exit(1)
        print("[+] Server is accessible")
        
        detector = SQLInjectionDetector()
        
        ml_classifier = None
        if args.ml or args.ml_model or args.train_ml:
            ml_classifier = SQLInjectionMLClassifier(model_type='random_forest')
            if args.ml_model:
                try:
                    ml_classifier.load_model(args.ml_model)
                    print(f"[+] ML model loaded from {args.ml_model}")
                except Exception as e:
                    print(f"[!] Error loading ML model: {e}")
                    ml_classifier = None
        
        print_summary(args)
        
        endpoints = args.endpoints if args.endpoints else ['/']
        
        methods = []
        if args.method == 'BOTH':
            methods = ['GET', 'POST']
        else:
            methods = [args.method]
        
        all_results = {}
        
        for method in methods:
            print(f"\n[*] Scanning with {method} method...")
            
            for endpoint in endpoints:
                full_url = args.url.rstrip('/') + '/' + endpoint.lstrip('/')
                print(f"\n[*] Scanning: {full_url} ({method})")
                
                params = None
                if args.params:
                    params = [p.strip() for p in args.params.split(',')]
                
                try:
                    scan_results = scanner.scan_endpoint(
                        full_url,
                        method=method,
                        params=params,
                        payloads=payloads,
                        forcedParams=forcedParameters,
                        forcedValues=forcedValues
                    )
                except KeyboardInterrupt:
                    print("\n[!] Scan interrupted by user")
                    print("[*] Partial results will be saved...")
                    break
                
            analyzed_results = []
            vuln_found_in_param = False
            
            boolean_responses = {'true': [], 'false': []}
            
            for result in scan_results:
                if result.get('connection_error') or result.get('error'):
                    continue
                
                payload_info = result.get('payload_info', {})
                base_response = result.get('base_response', {})
                
                if result.get('is_boolean_test'):
                    boolean_type = result.get('boolean_type')
                    if boolean_type in ['true', 'false']:
                        boolean_responses[boolean_type].append(result)
                
                detector_result = detector.evaluate_payload(
                    payload_info,
                    base_response,
                    result
                )
                result['detector_result'] = detector_result
                
                analyzed_results.append(result)
            
            if boolean_responses['true'] and boolean_responses['false']:
                for true_resp in boolean_responses['true']:
                    for false_resp in boolean_responses['false']:
                        true_text = true_resp.get('text', '')
                        false_text = false_resp.get('text', '')
                        base_text = true_resp.get('base_response', {}).get('text', '')
                        
                        if true_text and false_text and base_text:
                            boolean_detected = detector.detect_boolean_blind_sqli(
                                base_text,
                                true_text,
                                false_text
                            )
                            
                            if boolean_detected:
                                for resp in [true_resp, false_resp]:
                                    if resp in analyzed_results:
                                        idx = analyzed_results.index(resp)
                                        analyzed_results[idx]['detector_result']['vulnerable'] = True
                                        analyzed_results[idx]['detector_result']['vulnerability_type'] = 'boolean_blind'
                                        analyzed_results[idx]['detector_result']['confidence'] = 'high'
                                        analyzed_results[idx]['detector_result']['evidence'].append(
                                            "Boolean-blind SQLi detected: Different responses for TRUE and FALSE conditions"
                                        )
                                vuln_found_in_param = True
                                print(f"    [!] BOOLEAN-BLIND SQLi DETECTED in {true_resp.get('param', 'unknown')}")
            
            for result in analyzed_results:
                detector_result = result.get('detector_result', {})
                base_response = result.get('base_response', {})
                
                if ml_classifier and ml_classifier.is_trained:
                    ml_result = ml_classifier.predict(
                        result,
                        base_response,
                        detector_result
                    )
                    result['ml_result'] = ml_result
                
                if args.verbose:
                    param_name = result.get('param', 'unknown')
                    payload_short = detector_result.get('payload', '')[:60]
                    status = result.get('status_code', 0)
                    resp_length = len(result.get('text', ''))
                    base_length = base_response.get('length', 0)
                    base_status = base_response.get('status_code', 200)
                    length_diff = abs(resp_length - base_length)
                    similarity = detector_result.get('indicators', {}).get('html_analysis', {}).get('similarity', 1.0)
                    
                    if detector_result.get('vulnerable'):
                        print(f"    [!] VULNERABILITY DETECTED in {param_name}")
                        print(f"        Payload: {payload_short}")
                        print(f"        Type: {detector_result.get('vulnerability_type')}, Confidence: {detector_result.get('confidence')}")
                        print(f"        Status: {base_status} -> {status}, Length: {base_length} -> {resp_length} (diff: {length_diff})")
                        print(f"        Similarity: {similarity:.2%}")
                        print(f"        Evidence: {', '.join(detector_result.get('evidence', [])[:3])}")
                        vuln_found_in_param = True
                    elif detector_result.get('confidence') in ['medium', 'high']:
                        print(f"    [?] Potential issue in {param_name}")
                        print(f"        Payload: {payload_short}")
                        print(f"        Status: {base_status} -> {status}, Length: {base_length} -> {resp_length} (diff: {length_diff}), Similarity: {similarity:.2%}")
                        print(f"        Evidence: {', '.join(detector_result.get('evidence', [])[:2])}")
                    elif result.get('is_boolean_test'):
                        print(f"    [*] Boolean test ({result.get('boolean_type', 'unknown')}) in {param_name}: length={resp_length}, status={status}, similarity={similarity:.2%}")
                    elif length_diff > 0 or status != base_status:
                        print(f"    [*] Response change in {param_name}: length={base_length} -> {resp_length} (diff: {length_diff}), status={base_status} -> {status}, similarity={similarity:.2%}")
                        print(f"        Payload: {payload_short[:50]}")
                        if length_diff > 50 or similarity < 0.90:
                            resp_preview = result.get('text', '')[:200].replace('\n', ' ')
                            print(f"        Response preview: {resp_preview}...")
            
            all_results[f"{endpoint}_{method}"] = {
                'url': full_url,
                'method': method,
                'results': analyzed_results
            }
            
            vuln_count = sum(1 for r in analyzed_results 
                           if r.get('detector_result', {}).get('vulnerable', False))
            
            potential_count = sum(1 for r in analyzed_results 
                                if r.get('detector_result', {}).get('confidence') in ['medium', 'high'] 
                                and not r.get('detector_result', {}).get('vulnerable', False))
            
            params_tested = set(r.get('param', 'unknown') for r in analyzed_results)
            print(f"  [*] Tested parameters: {', '.join(sorted(params_tested))}")
            
            significant_changes = sum(1 for r in analyzed_results 
                                    if r.get('detector_result', {}).get('indicators', {}).get('html_analysis', {}).get('length_diff', 0) > 20)
            
            if vuln_count > 0:
                print(f"  [!] Found {vuln_count} potential vulnerabilities")
                if potential_count > 0:
                    print(f"  [?] Also found {potential_count} potential issues (review with --verbose)")
            else:
                if potential_count > 0:
                    print(f"  [?] Found {potential_count} potential issues (use --verbose for details)")
                elif significant_changes > 0:
                    print(f"  [?] Found {significant_changes} responses with significant changes (review HTML report)")
                    print(f"  [*] Tip: Even if not marked as vulnerable, check the HTML report for detailed analysis")
                else:
                    print(f"  [+] No vulnerabilities detected")
                    if args.verbose:
                        print(f"  [*] Tip: If you know the exact parameter name, use --params to test it specifically")
                        print(f"  [*] Tip: Check the HTML report for detailed analysis of all responses")
                        print(f"  [*] Tip: Try with --attack all to test all payload types")
        
        if args.train_ml and ml_classifier:
            print("\n[*] Training ML model...")
            try:
                X, y = ml_classifier.generate_training_data_from_results(all_results)
                if len(X) > 0:
                    accuracy = ml_classifier.train(X, y)
                    model_path = 'sql_injection_model.pkl'
                    ml_classifier.save_model(model_path)
                    print(f"[+] Model trained with accuracy: {accuracy:.2%}")
                else:
                    print("[!] Not enough data to train model")
            except Exception as e:
                print(f"[!] Error training model: {e}")
        
        reporter = ReportGenerator()
        
        console_report = reporter.generate_console_report(all_results, verbose=args.verbose)
        print(console_report)
        
        if args.json:
            reporter.generate_json_report(all_results, args.json)
        elif args.report and args.report.endswith('.json'):
            reporter.generate_json_report(all_results, args.report)
        
        if args.report and args.report.endswith('.html'):
            reporter.generate_html_report(all_results, args.report)
        elif args.report and not args.report.endswith('.json'):
            html_path = args.report if args.report.endswith('.html') else args.report + '.html'
            reporter.generate_html_report(all_results, html_path)
        
        total_vulns = sum(
            sum(1 for r in endpoint_data.get('results', [])
                if r.get('detector_result', {}).get('vulnerable', False))
            for endpoint_data in all_results.values()
        )
        
        print(f"\n[*] Scan completed. Total vulnerabilities found: {total_vulns}")
        
        if total_vulns > 0:
            print("[!] WARNING: Vulnerabilities detected. Review the report for details.")
            sys.exit(1)
        else:
            print("[+] No vulnerabilities detected.")
            sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user (Ctrl+C)")
        print("[*] Exiting gracefully...")
        sys.exit(130)  # Código estándar para Ctrl+C
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        import traceback
        if args.verbose if 'args' in locals() else False:
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
