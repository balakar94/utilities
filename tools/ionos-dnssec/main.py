#!/usr/bin/env python3
"""IONOS DNSSEC DS manager"""

import argparse
import getpass
import http.client
import json
import os
import string
import sys
import urllib.error
import urllib.parse
import urllib.request

# Constants.
API_BASE = "https://api.hosting.ionos.com/dns/v1"
ZONES_URL = API_BASE + "/zones"
TIMEOUT = 20
DEFAULT_TTL = 3600
LANG = "en"
APP_TITLE = "IONOS DNSSEC DS Manager"
APP_VERSION = "1.0.0"

# BACK aborts to the previous menu; Quit exits via _quit().
BACK = object()

# Box geometry: 68 total, 64 inner.
BOX_INNER = 64
BOX_FILL = 66

CONFIRM_TOKENS = {
    "en": {"yes": ("y", "yes"), "no": ("n", "no")},
    "es": {"yes": ("s", "si", "y", "yes"), "no": ("n", "no")},
    "de": {"yes": ("j", "ja", "y", "yes"), "no": ("n", "nein", "no")},
}

# Colors (hardcoded ANSI).
ANSI_RESET = "\033[0m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_CYAN = "\033[36m"
ANSI_WHITE = "\033[37m"
ANSI_BOLD_WHITE = "\033[1;37m"
ANSI_BOLD_GREEN = "\033[1;32m"
ANSI_BOLD_YELLOW = "\033[1;33m"
ANSI_BOLD_MAGENTA = "\033[1;35m"
ANSI_BOLD_CYAN = "\033[1;36m"
ANSI_DIM_WHITE = "\033[2;37m"

COLOR_MODE = "auto"  # one of always|auto|never, set by setup_color()
COLOR_ENABLED = True  # master switch; use_color() still gates auto on TTY
CLEAR_ENABLED = True  # master switch for clearing screen on menu jumps

# State shown in per-step headers (never the secret itself).
CURRENT_MASKED = "--"
CURRENT_ZONE = "--"


def use_color():
    """Return True when ANSI colors should be emitted."""
    if COLOR_MODE == "never":
        return False
    if COLOR_MODE == "always":
        return True
    return bool(COLOR_ENABLED and sys.stdout.isatty())


def c(text, code):
    """Wrap text in an ANSI code when colors are enabled, else as-is."""
    if not code:
        return text
    if not use_color():
        return text
    return code + text + ANSI_RESET


def _parse_color_value(raw):
    """Normalize a color mode value; return always|auto|never or None."""
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if value in ("always", "auto", "never"):
        return value
    if value in ("1", "true", "yes", "y", "on"):
        return "always"
    if value in ("0", "false", "no", "n", "off"):
        return "never"
    return None


def setup_color(cli_color=None, cli_no_color=False):
    """Resolve COLOR_MODE/COLOR_ENABLED from CLI flags and IONOS_COLOR env."""
    global COLOR_MODE, COLOR_ENABLED
    env_mode = _parse_color_value(os.environ.get("IONOS_COLOR", ""))
    if cli_color in ("always", "auto", "never"):
        mode = cli_color
    elif env_mode is not None:
        mode = env_mode
    else:
        mode = "auto"
    COLOR_MODE = mode
    if cli_no_color or mode == "never":
        COLOR_ENABLED = False
    else:
        COLOR_ENABLED = True


# Localized strings
STRINGS = {
    "en": {
        "lang_prompt": "Choice: ",
        "lang_invalid": (
            "Invalid choice. Please enter 1, 2, 3 or 'en', 'es', 'de'."
        ),
        "lang_menu_title": "Choose language:",
        "welcome": "Welcome to the IONOS DNSSEC DS record tool.",
        "api_info": (
            "To use this tool you need an API key. Create one at "
            "https://developer.hosting.ionos.com"
        ),
        "key_format": (
            "The key consists of a public prefix and a secret. Authentication "
            "uses the header 'X-API-Key: <public>.<secret>'."
        ),
        "prompt_public": "Enter the public prefix of the API key: ",
        "prompt_secret": "Enter the secret of the API key, input hidden: ",
        "empty_public": "Public prefix must not be empty. Please try again.",
        "empty_secret": "Secret must not be empty. Please try again.",
        "using_masked": "Using API key: {masked}",
        "fetching_zones": "Fetching DNS zones ...",
        "zones_empty": "No DNS zones found for this API key.",
        "zones_header": "Available DNS zones:",
        "domain_label": "Domain",
        "zoneid_label": "ZoneID",
        "prompt_zone": "Choice: ",
        "zone_invalid": (
            "Invalid selection. Enter a number from the list or an exact "
            "domain name."
        ),
        "zone_selected": "Selected zone: {name} (ZoneID: {zone_id})",
        "prompt_ds": (
            "Enter DS content as '<keyTag> <algorithm> <digestType> "
            "<digest>': "
        ),
        "ds_example": (
            "Example: '12345 13 2 "
            "9ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678"
            "9'"
        ),
        "ds_error_parts": (
            "Invalid format. Expected exactly 4 parts separated by spaces: "
            "'<keyTag> <algorithm> <digestType> <digest>'."
        ),
        "ds_error_ints": (
            "Invalid format. The first three parts (keyTag, algorithm, "
            "digestType) must be integers."
        ),
        "ds_error_hex": (
            "Invalid format. The digest (4th part) must be hexadecimal (0-9, "
            "a-f, A-F)."
        ),
        "ds_error_keytag": (
            "Invalid format. keyTag must be between 0 and 65535."
        ),
        "ds_error_algorithm": (
            "Invalid format. algorithm must be between 0 and 255."
        ),
        "ds_error_digesttype": (
            "Invalid format. digestType must be 1 (SHA-1), 2 (SHA-256), 3 "
            "(GOST) or 4 (SHA-384)."
        ),
        "ds_warn_length": (
            "Digest has {length} hex chars; digestType {digest_type} usually "
            "uses {expected}. Continuing anyway."
        ),
        "prompt_ttl": "Enter TTL [default {default}]: ",
        "ttl_invalid": (
            "Invalid TTL. Enter a positive integer (1-2147483647) or press "
            "Enter for default {default}."
        ),
        "prompt_name": "Enter record name [default {default}]: ",
        "summary_title": "Request summary (NOT sent yet):",
        "summary_zone": "Zone ID: {zone_id}",
        "summary_record_name": "Record name: {name}",
        "summary_type": "Type: DS",
        "summary_content": "Content (DS): {content}",
        "summary_ttl": "TTL: {ttl}",
        "prompt_confirm": "Send this DS record now? {hint} ",
        "confirm_invalid": "Please answer with yes or no ([y/n]).",
        "cancelled": "Cancelled. Nothing was sent.",
        "sending": "Sending POST request ...",
        "success": "Success: DS record created (HTTP {status}).",
        "success_body": "Server response: {body}",
        "http_error": "HTTP error {status}: {reason}",
        "http_body": "Server message: {body}",
        "network_error": (
            "Network error: {detail}. Check your connection and try again."
        ),
        "unexpected_error": "Unexpected error: {detail}",
        "hint_401": (
            "Hint: 401 Unauthorized - the API key is missing or wrong. Check "
            "public prefix and secret."
        ),
        "hint_403": (
            "Hint: 403 Forbidden - the key has no permission for this "
            "zone/record."
        ),
        "hint_404": (
            "Hint: 404 Not Found - the zone ID does not exist (or belongs to "
            "another account)."
        ),
        "hint_422": (
            "Hint: 422 Unprocessable Entity - the server rejected the data "
            "(bad DS content, TTL or name)."
        ),
        "hint_400": (
            "Hint: 400 Bad Request - the request was malformed or contained "
            "invalid parameters."
        ),
        "hint_429": (
            "Hint: 429 Too Many Requests - you are being rate limited. Wait a "
            "moment and retry."
        ),
        "list_ds": "Checking existing DS records ...",
        "no_ds": "No existing DS records found for this zone.",
        "existing_ds": "Existing DS records:",
        "conflict_warning": (
            "Updates might conflict with active services. Records of "
            "conflicting services may be deactivated. Check with your DNS "
            "operator before changing DS records."
        ),
        "choose_action": "Choice: ",
        "action_invalid": "Invalid option. Please enter 1, 2 or 3.",
        "option_update": "Update in place (PUT, recommended)",
        "option_create": "Create additional (POST)",
        "option_delete": "Delete",
        "select_record": "Choice: ",
        "record_invalid": (
            "Invalid selection. Enter a number between 1 and {count}."
        ),
        "auto_selected": "Auto-selected the only DS record (id: {id}).",
        "diff_current": "Current: content={content} TTL={ttl}",
        "diff_new": "New:     content={content} TTL={ttl}",
        "confirm_update": "Update this DS record in place? {hint} ",
        "confirm_delete": "Delete DS record {id}? {hint} ",
        "confirm_delete_again": (
            "Really delete? This cannot be undone. {hint} "
        ),
        "sending_update": "Sending PUT request ...",
        "sending_delete": "Sending DELETE request ...",
        "update_ok": "Success: DS record updated (HTTP {status}).",
        "delete_ok": "Success: DS record deleted (HTTP {status}).",
        "menu_title": "What do you want to do next?",
        "menu_retry": "Manage DS for this zone again",
        "menu_other": "Choose another zone",
        "prompt_menu": "Choice: ",
        "menu_invalid": "Invalid option. Please enter 1, 2 or 3.",
        "goodbye": "Goodbye.",
        "interrupted": "Interrupted by user. Goodbye.",
        "fetch_retry": "Could not fetch zones.",
        "fetch_retry_invalid": "Invalid option. Please enter 1 or 2.",
        "option_retry": "Retry",
        "option_quit": "Quit",
        "prompt_choice_2": "Choice: ",
        "info_prefix": "INFO:",
        "ok_prefix": "OK:",
        "warn_prefix": "WARN:",
        "error_prefix": "ERROR:",
        "step_1_name": "Language",
        "step_2_name": "API key",
        "step_3_name": "Select zone",
        "step_4_name": "DS records",
        "step_of": "Step {n} of {total} -- {name}",
        "ctx_lang": "Lang",
        "ctx_key": "Key",
        "ctx_zone": "Zone",
        "back_label": "Back",
        "quit_label": "Quit",
        "abort_msg": "Aborted. Returning to previous menu.",
        "truncation_note": (
            "Note: content truncated for display; full value is used."
        ),
        "th_n": "N",
        "th_id": "ID",
        "th_content": "Content (DS)",
        "th_ttl": "TTL",
        "confirm_hint_q": "[y/n, q=back]",
        "action_menu_title": "Choose DS action:",
        "record_menu_title": "Select a DS record:",
    },
    "es": {
        "lang_prompt": "Elige: ",
        "lang_invalid": (
            "Opcion no valida. Introduce 1, 2, 3 o 'en', 'es', 'de'."
        ),
        "lang_menu_title": "Elige idioma:",
        "welcome": (
            "Bienvenido a la herramienta de IONOS para crear registros DS de "
            "DNSSEC."
        ),
        "api_info": (
            "Para usar esta herramienta necesitas una clave API. Creala en "
            "https://developer.hosting.ionos.es/?source=IonosControlPanel"
        ),
        "key_format": (
            "La clave consta de un prefijo publico y un secreto. La "
            "autenticacion usa la cabecera 'X-API-Key: <publico>.<secreto>'."
        ),
        "prompt_public": "Introduce el prefijo publico de la clave API: ",
        "prompt_secret": (
            "Introduce el secreto de la clave API, entrada oculta: "
        ),
        "empty_public": (
            "El prefijo publico no puede estar vacio. Intentalo de nuevo."
        ),
        "empty_secret": "El secreto no puede estar vacio. Intentalo de nuevo.",
        "using_masked": "Usando clave API: {masked}",
        "fetching_zones": "Obteniendo zonas DNS ...",
        "zones_empty": "No se encontraron zonas DNS para esta clave API.",
        "zones_header": "Zonas DNS disponibles:",
        "domain_label": "Dominio",
        "zoneid_label": "ZoneID",
        "prompt_zone": "Elige: ",
        "zone_invalid": (
            "Seleccion no valida. Introduce un numero de la lista o un nombre "
            "de dominio exacto."
        ),
        "zone_selected": "Zona elegida: {name} (ZoneID: {zone_id})",
        "prompt_ds": (
            "Introduce el contenido DS como '<keyTag> <algorithm> "
            "<digestType> <digest>': "
        ),
        "ds_example": (
            "Ejemplo: '12345 13 2 "
            "9ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678"
            "9'"
        ),
        "ds_error_parts": (
            "Formato no valido. Se esperan exactamente 4 partes separadas por "
            "espacios: '<keyTag> <algorithm> <digestType> <digest>'."
        ),
        "ds_error_ints": (
            "Formato no valido. Las tres primeras partes (keyTag, algorithm, "
            "digestType) deben ser numeros enteros."
        ),
        "ds_error_hex": (
            "Formato no valido. El digest (4.a parte) debe ser hexadecimal "
            "(0-9, a-f, A-F)."
        ),
        "ds_error_keytag": (
            "Formato no valido. keyTag debe estar entre 0 y 65535."
        ),
        "ds_error_algorithm": (
            "Formato no valido. algorithm debe estar entre 0 y 255."
        ),
        "ds_error_digesttype": (
            "Formato no valido. digestType debe ser 1 (SHA-1), 2 (SHA-256), 3 "
            "(GOST) o 4 (SHA-384)."
        ),
        "ds_warn_length": (
            "El digest tiene {length} caracteres hex; digestType "
            "{digest_type} suele usar {expected}. Se continua de todos modos."
        ),
        "prompt_ttl": "Introduce el TTL [por defecto {default}]: ",
        "ttl_invalid": (
            "TTL no valido. Introduce un entero positivo (1-2147483647) o "
            "pulsa Enter para usar {default}."
        ),
        "prompt_name": (
            "Introduce el nombre del registro [por defecto {default}]: "
        ),
        "summary_title": "Resumen de la peticion (AUN no enviada):",
        "summary_zone": "Zone ID: {zone_id}",
        "summary_record_name": "Nombre del registro: {name}",
        "summary_type": "Tipo: DS",
        "summary_content": "Contenido (DS): {content}",
        "summary_ttl": "TTL: {ttl}",
        "prompt_confirm": "Enviar este registro DS ahora? {hint} ",
        "confirm_invalid": "Responde si o no ([s/n]).",
        "cancelled": "Cancelado. No se ha enviado nada.",
        "sending": "Enviando la peticion POST ...",
        "success": "Exito: registro DS creado (HTTP {status}).",
        "success_body": "Respuesta del servidor: {body}",
        "http_error": "Error HTTP {status}: {reason}",
        "http_body": "Mensaje del servidor: {body}",
        "network_error": (
            "Error de red: {detail}. Comprueba tu conexion e intentalo de "
            "nuevo."
        ),
        "unexpected_error": "Error inesperado: {detail}",
        "hint_401": (
            "Pista: 401 No autorizado - la clave API falta o es incorrecta. "
            "Revisa el prefijo publico y el secreto."
        ),
        "hint_403": (
            "Pista: 403 Prohibido - la clave no tiene permiso para esta "
            "zona/registro."
        ),
        "hint_404": (
            "Pista: 404 No encontrado - el Zone ID no existe (o pertenece a "
            "otra cuenta)."
        ),
        "hint_422": (
            "Pista: 422 Entidad no procesable - el servidor rechazo los datos "
            "(contenido DS, TTL o nombre incorrectos)."
        ),
        "hint_400": (
            "Pista: 400 Solicitud incorrecta - la peticion esta mal formada o "
            "contiene parametros no validos."
        ),
        "hint_429": (
            "Pista: 429 Demasiadas peticiones - estas limitado por tasa. "
            "Espera un momento y reintenta."
        ),
        "list_ds": "Comprobando registros DS existentes ...",
        "no_ds": "No se encontraron registros DS existentes para esta zona.",
        "existing_ds": "Registros DS existentes:",
        "conflict_warning": (
            "Las actualizaciones pueden entrar en conflicto con servicios "
            "activos. Los registros de servicios en conflicto podrian "
            "desactivarse. Consulta con tu operador DNS antes de cambiar "
            "registros DS."
        ),
        "choose_action": "Elige: ",
        "action_invalid": "Opcion no valida. Introduce 1, 2 o 3.",
        "option_update": "Actualizar en el mismo registro (PUT, recomendado)",
        "option_create": "Crear adicional (POST)",
        "option_delete": "Eliminar",
        "select_record": "Elige: ",
        "record_invalid": (
            "Seleccion no valida. Introduce un numero entre 1 y {count}."
        ),
        "auto_selected": (
            "Registro DS unico seleccionado automaticamente (id: {id})."
        ),
        "diff_current": "Actual:  contenido={content} TTL={ttl}",
        "diff_new": "Nuevo:   contenido={content} TTL={ttl}",
        "confirm_update": (
            "Actualizar este registro DS en el mismo sitio? {hint} "
        ),
        "confirm_delete": "Eliminar el registro DS {id}? {hint} ",
        "confirm_delete_again": (
            "Seguro que quieres eliminarlo? No se puede deshacer. {hint} "
        ),
        "sending_update": "Enviando la peticion PUT ...",
        "sending_delete": "Enviando la peticion DELETE ...",
        "update_ok": "Exito: registro DS actualizado (HTTP {status}).",
        "delete_ok": "Exito: registro DS eliminado (HTTP {status}).",
        "menu_title": "Que quieres hacer ahora?",
        "menu_retry": "Gestionar DS de esta zona de nuevo",
        "menu_other": "Elegir otra zona",
        "prompt_menu": "Elige: ",
        "menu_invalid": "Opcion no valida. Introduce 1, 2 o 3.",
        "goodbye": "Adios.",
        "interrupted": "Interrumpido por el usuario. Adios.",
        "fetch_retry": "No se pudieron obtener las zonas.",
        "fetch_retry_invalid": "Opcion no valida. Introduce 1 o 2.",
        "option_retry": "Reintentar",
        "option_quit": "Salir",
        "prompt_choice_2": "Elige: ",
        "info_prefix": "INFO:",
        "ok_prefix": "OK:",
        "warn_prefix": "AVISO:",
        "error_prefix": "ERROR:",
        "step_1_name": "Idioma",
        "step_2_name": "Clave API",
        "step_3_name": "Elegir zona",
        "step_4_name": "Registros DS",
        "step_of": "Paso {n} de {total} -- {name}",
        "ctx_lang": "Idioma",
        "ctx_key": "Clave",
        "ctx_zone": "Zona",
        "back_label": "Atras",
        "quit_label": "Salir",
        "abort_msg": "Abortado. Volviendo al menu anterior.",
        "truncation_note": (
            "Nota: contenido truncado en pantalla; se usa el valor completo."
        ),
        "th_n": "N",
        "th_id": "ID",
        "th_content": "Contenido (DS)",
        "th_ttl": "TTL",
        "confirm_hint_q": "[s/n, q=atras]",
        "action_menu_title": "Elige la accion DS:",
        "record_menu_title": "Elige un registro DS:",
    },
    "de": {
        "lang_prompt": "Wahl: ",
        "lang_invalid": (
            "Ungueltige Auswahl. Bitte 1, 2, 3 oder 'en', 'es', 'de' "
            "eingeben."
        ),
        "lang_menu_title": "Sprache waehlen:",
        "welcome": (
            "Willkommen beim IONOS-Tool zum Anlegen von DNSSEC-DS-Records."
        ),
        "api_info": (
            "Zur Nutzung brauchst du einen API-Schluessel. Erstelle ihn unter "
            "https://developer.hosting.ionos.de/"
        ),
        "key_format": (
            "Der Schluessel besteht aus einem oeffentlichen Praefix und einem "
            "Secret. Die Authentifizierung nutzt den Header 'X-API-Key: "
            "<public>.<secret>'."
        ),
        "prompt_public": (
            "Oeffentliches Praefix des API-Schluessels eingeben: "
        ),
        "prompt_secret": (
            "Secret des API-Schluessels eingeben, Eingabe verdeckt: "
        ),
        "empty_public": (
            "Das oeffentliche Praefix darf nicht leer sein. Bitte erneut "
            "versuchen."
        ),
        "empty_secret": (
            "Das Secret darf nicht leer sein. Bitte erneut versuchen."
        ),
        "using_masked": "Verwendeter API-Schluessel: {masked}",
        "fetching_zones": "DNS-Zonen werden abgerufen ...",
        "zones_empty": "Keine DNS-Zonen fuer diesen API-Schluessel gefunden.",
        "zones_header": "Verfuegbare DNS-Zonen:",
        "domain_label": "Domain",
        "zoneid_label": "ZoneID",
        "prompt_zone": "Wahl: ",
        "zone_invalid": (
            "Ungueltige Auswahl. Nummer aus der Liste oder exakten "
            "Domainnamen eingeben."
        ),
        "zone_selected": "Gewaehlte Zone: {name} (ZoneID: {zone_id})",
        "prompt_ds": (
            "DS-Inhalt eingeben als '<keyTag> <algorithm> <digestType> "
            "<digest>': "
        ),
        "ds_example": (
            "Beispiel: '12345 13 2 "
            "9ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678"
            "9'"
        ),
        "ds_error_parts": (
            "Ungueltiges Format. Genau 4 durch Leerzeichen getrennte Teile "
            "erwartet: '<keyTag> <algorithm> <digestType> <digest>'."
        ),
        "ds_error_ints": (
            "Ungueltiges Format. Die ersten drei Teile (keyTag, algorithm, "
            "digestType) muessen Ganzzahlen sein."
        ),
        "ds_error_hex": (
            "Ungueltiges Format. Der Digest (4. Teil) muss hexadezimal sein "
            "(0-9, a-f, A-F)."
        ),
        "ds_error_keytag": (
            "Ungueltiges Format. keyTag muss zwischen 0 und 65535 liegen."
        ),
        "ds_error_algorithm": (
            "Ungueltiges Format. algorithm muss zwischen 0 und 255 liegen."
        ),
        "ds_error_digesttype": (
            "Ungueltiges Format. digestType muss 1 (SHA-1), 2 (SHA-256), 3 "
            "(GOST) oder 4 (SHA-384) sein."
        ),
        "ds_warn_length": (
            "Der Digest hat {length} Hex-Zeichen; digestType {digest_type} "
            "nutzt normalerweise {expected}. Fahre trotzdem fort."
        ),
        "prompt_ttl": "TTL eingeben [Standard {default}]: ",
        "ttl_invalid": (
            "Ungueltige TTL. Positive Ganzzahl (1-2147483647) eingeben oder "
            "Enter fuer Standard {default} druecken."
        ),
        "prompt_name": "Record-Namen eingeben [Standard {default}]: ",
        "summary_title": "Zusammenfassung der Anfrage (NOCH nicht gesendet):",
        "summary_zone": "Zone-ID: {zone_id}",
        "summary_record_name": "Record-Name: {name}",
        "summary_type": "Typ: DS",
        "summary_content": "Inhalt (DS): {content}",
        "summary_ttl": "TTL: {ttl}",
        "prompt_confirm": "Diesen DS-Record jetzt senden? {hint} ",
        "confirm_invalid": "Bitte mit Ja oder Nein antworten ([j/n]).",
        "cancelled": "Abgebrochen. Es wurde nichts gesendet.",
        "sending": "POST-Anfrage wird gesendet ...",
        "success": "Erfolg: DS-Record angelegt (HTTP {status}).",
        "success_body": "Serverantwort: {body}",
        "http_error": "HTTP-Fehler {status}: {reason}",
        "http_body": "Servermeldung: {body}",
        "network_error": (
            "Netzwerkfehler: {detail}. Verbindung pruefen und erneut "
            "versuchen."
        ),
        "unexpected_error": "Unerwarteter Fehler: {detail}",
        "hint_401": (
            "Hinweis: 401 Unauthorized - API-Schluessel fehlt oder ist "
            "falsch. Praefix und Secret pruefen."
        ),
        "hint_403": (
            "Hinweis: 403 Forbidden - der Schluessel hat keine Berechtigung "
            "fuer diese Zone/diesen Record."
        ),
        "hint_404": (
            "Hinweis: 404 Not Found - die Zone-ID existiert nicht (oder "
            "gehoert zu einem anderen Konto)."
        ),
        "hint_422": (
            "Hinweis: 422 Unprocessable Entity - der Server hat die Daten "
            "abgelehnt (DS-Inhalt, TTL oder Name pruefen)."
        ),
        "hint_400": (
            "Hinweis: 400 Bad Request - die Anfrage ist fehlerhaft oder "
            "enthaelt ungueltige Parameter."
        ),
        "hint_429": (
            "Hinweis: 429 Too Many Requests - Rate Limit erreicht. Kurz "
            "warten und erneut versuchen."
        ),
        "list_ds": "Vorhandene DS-Records werden geprueft ...",
        "no_ds": "Keine vorhandenen DS-Records fuer diese Zone gefunden.",
        "existing_ds": "Vorhandene DS-Records:",
        "conflict_warning": (
            "Updates koennen mit aktiven Services in Konflikt geraten. "
            "Records kollidierender Services werden ggf. deaktiviert. Vor dem "
            "Aendern von DS-Records mit dem DNS-Betreiber abstimmen."
        ),
        "choose_action": "Wahl: ",
        "action_invalid": "Ungueltige Option. Bitte 1, 2 oder 3 eingeben.",
        "option_update": "In place aktualisieren (PUT, empfohlen)",
        "option_create": "Zusaetzlich anlegen (POST)",
        "option_delete": "Loeschen",
        "select_record": "Wahl: ",
        "record_invalid": (
            "Ungueltige Auswahl. Nummer zwischen 1 und {count} eingeben."
        ),
        "auto_selected": "Einziger DS-Record automatisch gewaehlt (id: {id}).",
        "diff_current": "Aktuell: Inhalt={content} TTL={ttl}",
        "diff_new": "Neu:     Inhalt={content} TTL={ttl}",
        "confirm_update": "Diesen DS-Record in place aktualisieren? {hint} ",
        "confirm_delete": "DS-Record {id} loeschen? {hint} ",
        "confirm_delete_again": (
            "Wirklich loeschen? Dies kann nicht rueckgaengig gemacht werden. "
            "{hint} "
        ),
        "sending_update": "PUT-Anfrage wird gesendet ...",
        "sending_delete": "DELETE-Anfrage wird gesendet ...",
        "update_ok": "Erfolg: DS-Record aktualisiert (HTTP {status}).",
        "delete_ok": "Erfolg: DS-Record geloescht (HTTP {status}).",
        "menu_title": "Wie soll es weitergehen?",
        "menu_retry": "DS fuer diese Zone erneut verwalten",
        "menu_other": "Andere Zone waehlen",
        "prompt_menu": "Wahl: ",
        "menu_invalid": "Ungueltige Option. Bitte 1, 2 oder 3 eingeben.",
        "goodbye": "Auf Wiedersehen.",
        "interrupted": "Durch Benutzer abgebrochen. Auf Wiedersehen.",
        "fetch_retry": "Zonen konnten nicht abgerufen werden.",
        "fetch_retry_invalid": "Ungueltige Option. Bitte 1 oder 2 eingeben.",
        "option_retry": "Wiederholen",
        "option_quit": "Beenden",
        "prompt_choice_2": "Wahl: ",
        "info_prefix": "INFO:",
        "ok_prefix": "OK:",
        "warn_prefix": "WARNUNG:",
        "error_prefix": "FEHLER:",
        "step_1_name": "Sprache",
        "step_2_name": "API-Schluessel",
        "step_3_name": "Zone waehlen",
        "step_4_name": "DS-Records",
        "step_of": "Schritt {n} von {total} -- {name}",
        "ctx_lang": "Sprache",
        "ctx_key": "Schluessel",
        "ctx_zone": "Zone",
        "back_label": "Zurueck",
        "quit_label": "Beenden",
        "abort_msg": "Abgebrochen. Rueckkehr zum vorherigen Menue.",
        "truncation_note": (
            "Hinweis: Inhalt gekuerzt dargestellt; der volle Wert wird "
            "verwendet."
        ),
        "th_n": "N",
        "th_id": "ID",
        "th_content": "Inhalt (DS)",
        "th_ttl": "TTL",
        "confirm_hint_q": "[j/n, q=zurueck]",
        "action_menu_title": "DS-Aktion waehlen:",
        "record_menu_title": "DS-Record waehlen:",
    },
}

# Helpers.


def t(key):
    """Return the string for key in the active language."""
    lang_table = STRINGS.get(LANG, STRINGS["en"])
    value = lang_table.get(key)
    if isinstance(value, str):
        return value
    fallback = STRINGS["en"].get(key)
    if isinstance(fallback, str):
        return fallback
    return str(key)


def mask_token(token):
    """Mask an API token, showing at most 4 chars of the public prefix.

    Never reveals any character of the secret (the part after the dot).
    """
    if not token:
        return "****"
    public = str(token).split(".", 1)[0]
    return public[:4] + "****"


def _confirm_tokens():
    """Return (yes, no) token tuples for the active language."""
    table = CONFIRM_TOKENS.get(LANG, CONFIRM_TOKENS["en"])
    return table["yes"], table["no"]


def _norm_confirm(raw):
    """Normalize confirm input; 'si' with accent equals 'si'."""
    text = str(raw).strip().lower()
    return text.replace("sí", "si")


def is_yes(raw):
    """True when input is an affirmative in the active language."""
    yes, _ = _confirm_tokens()
    return _norm_confirm(raw) in yes


def is_no(raw):
    """True when input is a negative in the active language."""
    _, no = _confirm_tokens()
    return _norm_confirm(raw) in no


def _confirm_hint_q():
    """Confirm hint including abort (localized)."""
    return t("confirm_hint_q")


def _strip_ansi(text):
    """Strip ANSI ESC[...m sequences without regex."""
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\033" and i + 1 < n and text[i + 1] == "[":
            j = i + 2
            while j < n and text[j] != "m":
                j += 1
            i = j + 1 if j < n else n
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _visible_len(text):
    """Visible length ignoring ANSI sequences."""
    return len(_strip_ansi(str(text)))


def _wrap_plain(text, width=BOX_INNER):
    """Wrap plain text at width on word boundaries."""
    text = str(text).replace("\n", " ").replace("\r", " ")
    words = text.split()
    if not words:
        return [""]
    lines = []
    cur = ""
    for word in words:
        w = word
        while len(w) > width:
            if cur:
                lines.append(cur)
                cur = ""
            lines.append(w[:width])
            w = w[width:]
        if not cur:
            cur = w
        elif len(cur) + 1 + len(w) <= width:
            cur = cur + " " + w
        else:
            lines.append(cur)
            cur = w
    if cur or not lines:
        lines.append(cur)
    return lines


def _box_border(color):
    """Top/bottom border (68 cols), optionally colored."""
    return c("+" + "-" * BOX_FILL + "+", color)


def _box_edge(color):
    """Box edges, optionally colored."""
    if color and use_color():
        return c("|  ", color), c("|", color)
    return "|  ", "|"


def _print_box_line(content, border_color):
    """Print one box line padded to 64 visible columns."""
    left, right = _box_edge(border_color)
    vis = _visible_len(content)
    if vis > BOX_INNER:
        plain = _strip_ansi(content)
        content = plain[:BOX_INNER]
        vis = BOX_INNER
    padded = content + (" " * (BOX_INNER - vis))
    print(left + padded + right)


def box(title, body_lines, footer_lines=None, border_color="", title_color=""):
    """Print a boxed block (68 total, 64 inner). Prompts stay below the box."""
    if body_lines is None:
        body_lines = []
    if footer_lines is None:
        footer_lines = []
    print(_box_border(border_color))
    for tline in _wrap_plain(_strip_ansi(str(title)), BOX_INNER):
        padded = tline.ljust(BOX_INNER)
        shown = c(padded, title_color) if title_color else padded
        _print_box_line(shown, border_color)
    for raw in body_lines:
        line = str(raw)
        if _visible_len(line) > BOX_INNER and "\033" in line:
            for wline in _wrap_plain(_strip_ansi(line), BOX_INNER):
                _print_box_line(wline, border_color)
        elif _visible_len(line) > BOX_INNER:
            for wline in _wrap_plain(line, BOX_INNER):
                _print_box_line(wline, border_color)
        else:
            _print_box_line(line, border_color)
    if footer_lines:
        divider = "|" + "-" * BOX_FILL + "|"
        print(c(divider, border_color) if border_color else divider)
        for raw in footer_lines:
            line = str(raw)
            if _visible_len(line) > BOX_INNER:
                plain = _strip_ansi(line) if "\033" in line else line
                for wline in _wrap_plain(plain, BOX_INNER):
                    _print_box_line(wline, border_color)
            else:
                _print_box_line(line, border_color)
    print(_box_border(border_color))


def print_header():
    """Print the app header box once."""
    box(APP_TITLE, [t("welcome")],
        border_color=ANSI_BOLD_WHITE, title_color=ANSI_BOLD_WHITE)


def clear_screen():
    """Clear screen on menu jumps when TTY and not disabled."""
    if not CLEAR_ENABLED:
        return
    no_clear = os.environ.get("IONOS_NO_CLEAR", "").strip().lower()
    if no_clear in ("1", "true", "yes", "y", "on"):
        return
    try:
        if not sys.stdout.isatty():
            return
    except (OSError, ValueError):
        return
    try:
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")
    except OSError:
        try:
            print("\n" * 60)
        except OSError:
            return


def print_step(step_no):
    """Print the step header box with language/key/zone context."""
    clear_screen()
    box(APP_TITLE, [t("welcome")],
        border_color=ANSI_BOLD_WHITE, title_color=ANSI_BOLD_WHITE)
    names = {
        1: t("step_1_name"),
        2: t("step_2_name"),
        3: t("step_3_name"),
        4: t("step_4_name"),
    }
    name = names.get(step_no, "")
    title = t("step_of").format(n=step_no, total=4, name=name)
    ctx = (
        c(t("ctx_lang") + ": ", ANSI_DIM) + c(LANG, ANSI_BLUE)
        + c(" | " + t("ctx_key") + ": ", ANSI_DIM)
        + c(CURRENT_MASKED, ANSI_BLUE)
        + c(" | " + t("ctx_zone") + ": ", ANSI_DIM)
        + c(CURRENT_ZONE, ANSI_BLUE)
    )
    if not use_color():
        ctx = "{lang}: {l} | {key}: {k} | {zone}: {z}".format(
            lang=t("ctx_lang"), l=LANG, key=t("ctx_key"), k=CURRENT_MASKED,
            zone=t("ctx_zone"), z=CURRENT_ZONE)
    box(title, [ctx],
        border_color=ANSI_CYAN, title_color=ANSI_CYAN)


def print_info(message):
    """Print a progress message with the INFO prefix."""
    print(c(t("info_prefix") + " " + str(message), ANSI_CYAN))


def print_ok(message):
    """Print a success message with the OK prefix."""
    print(c(t("ok_prefix") + " " + str(message), ANSI_GREEN))


def print_warn(message):
    """Print a WARN box."""
    title = t("warn_prefix")
    box(title, [str(message)],
        border_color=ANSI_YELLOW, title_color=ANSI_YELLOW)


def print_error(message):
    """Print an ERROR box."""
    title = t("error_prefix")
    box(title, [str(message)],
        border_color=ANSI_RED, title_color=ANSI_RED)


def _style_prompt(raw):
    """Style a prompt; brackets dimmed. Prompt stays below boxes."""
    text = str(raw)
    if not use_color():
        return text
    start = text.find("[")
    end = text.find("]", start) if start != -1 else -1
    if start != -1 and end != -1:
        base = text[:start]
        hint = text[start:end + 1]
        rest = text[end + 1:]
        return (
            c(base, ANSI_BOLD_WHITE) + c(hint, ANSI_DIM)
            + c(rest, ANSI_BOLD_WHITE)
        )
    return c(text, ANSI_BOLD_WHITE)


def _prompt_input(raw_prompt):
    """input() with a styled prompt below any box."""
    return input(_style_prompt(raw_prompt))


def _quit():
    """Print goodbye and exit 0."""
    print(t("goodbye"))
    sys.exit(0)


def _is_quit_token(raw):
    """True for quit tokens 9/q."""
    return str(raw).strip().lower() in ("9", "q")


def _is_back_token(raw):
    """True for the back token 0."""
    return str(raw).strip() == "0"


def _print_abort():
    """Inform about abort to the previous menu."""
    print_info(t("abort_msg"))


def choose_language():
    """Ask the interface language."""
    global LANG
    aliases = {
        "1": "en", "en": "en", "english": "en",
        "2": "es", "es": "es", "espanol": "es", "spanish": "es",
        "3": "de", "de": "de", "deutsch": "de", "german": "de",
    }
    while True:
        print_step(1)
        num1 = c("1)", ANSI_BOLD_YELLOW) + " English"
        num2 = c("2)", ANSI_BOLD_YELLOW) + " Espanol"
        num3 = c("3)", ANSI_BOLD_YELLOW) + " Deutsch"
        quit_line = c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label")
        box(t("lang_menu_title"), [num1, num2, num3, quit_line],
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("lang_prompt")).strip().lower()
        if _is_quit_token(raw):
            _quit()
        if raw == "espa" + chr(241) + "ol":
            LANG = "es"
            return LANG
        if raw in aliases:
            LANG = aliases[raw]
            return LANG
        print_error(t("lang_invalid"))


def _read_secret(prompt):
    """Read the secret without echo; fallback to plain input."""
    styled = _style_prompt(prompt)
    try:
        return getpass.getpass(styled)
    except OSError:
        return input(styled)


def get_api_token():
    """Prompt for public prefix and secret. Bare 0 aborts; q is literal."""
    global CURRENT_MASKED
    print_step(2)
    while True:
        public = _prompt_input(t("prompt_public")).strip()
        if _is_back_token(public):
            return BACK
        if not public:
            print_error(t("empty_public"))
            continue
        secret = _read_secret(t("prompt_secret")).strip()
        if _is_back_token(secret):
            _print_abort()
            return BACK
        if not secret:
            print_error(t("empty_secret"))
            continue
        token = public + "." + secret
        CURRENT_MASKED = mask_token(token)
        print_ok(t("using_masked").format(masked=CURRENT_MASKED))
        return token


def _hint_for_status(status):
    """Return a hint for a known HTTP status, else empty string."""
    hints = {
        400: "hint_400",
        401: "hint_401",
        403: "hint_403",
        404: "hint_404",
        422: "hint_422",
        429: "hint_429",
    }
    key = hints.get(status)
    return t(key) if key else ""


def _shorten(text, limit=1000):
    """Truncate long server output for display."""
    if text is None:
        return ""
    text = str(text)
    if len(text) > limit:
        return text[:limit] + "..."
    return text


def _truncate_content(content, limit=30):
    """Truncate DS content for table display."""
    text = str(content)
    if len(text) <= limit:
        return text
    if limit <= 3:
        return text[:limit]
    return text[:limit - 3] + "..."


def _ds_row(n, rec_id, content, ttl, content_limit=30):
    """Build one DS table row fitting 64 visible columns."""
    n_s = str(n)
    id_s = str(rec_id)
    ttl_s = str(ttl)
    fixed = len(n_s) + len(id_s) + len(ttl_s) + 9
    budget = BOX_INNER - fixed
    budget = max(budget, 10)
    budget = min(budget, content_limit)
    shown = _truncate_content(content, budget)
    row = f"{n_s} | {id_s} | {shown} | {ttl_s}"
    if len(row) > BOX_INNER:
        overflow = len(row) - BOX_INNER
        shown2 = _truncate_content(shown, max(10, len(shown) - overflow))
        row = f"{n_s} | {id_s} | {shown2} | {ttl_s}"
    return row


def api_request(method, url, token, payload=None):
    """Send an API request; return (status, data) or (None, None) on error."""
    headers = {"X-API-Key": token, "Accept": "application/json"}
    body = None
    try:
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url, data=body, method=method, headers=headers
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            status = response.status
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        try:
            err_body = exc.read().decode("utf-8", errors="replace")
        except (OSError, ValueError, http.client.HTTPException):
            err_body = ""
        print_error(t("http_error").format(status=exc.code, reason=exc.reason))
        if err_body.strip():
            print_error(t("http_body").format(body=_shorten(err_body.strip())))
        hint = _hint_for_status(exc.code)
        if hint:
            print_info(hint)
        return None, None
    except urllib.error.URLError as exc:
        print_error(t("network_error").format(detail=exc.reason))
        return None, None
    except (OSError, ValueError, TypeError, http.client.HTTPException) as exc:
        print_error(t("network_error").format(detail=exc))
        return None, None
    if not raw.strip():
        return status, None
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def list_ds_records(token, zone_id):
    """Fetch DS records for a zone; None when the request failed."""
    print_info(t("list_ds"))
    url = (
        ZONES_URL
        + "/"
        + urllib.parse.quote(str(zone_id), safe="")
        + "?recordType=DS"
    )
    status, data = api_request("GET", url, token)
    if status is None:
        return None
    records = []
    if isinstance(data, dict):
        records = data.get("records", [])
    elif isinstance(data, list):
        records = data
    if not isinstance(records, list):
        return []
    return [
        record
        for record in records
        if isinstance(record, dict)
        and str(record.get("type", "")).upper() == "DS"
    ]


def list_zones(token):
    """Fetch zones; empty list when none, None when the request failed."""
    print_info(t("fetching_zones"))
    status, data = api_request("GET", ZONES_URL, token)
    if status is None:
        return None
    if isinstance(data, str):
        print_error(
            t("unexpected_error").format(detail="invalid JSON in zone list"))
        return None
    if not isinstance(data, list):
        print_error(
            t("unexpected_error").format(detail="unexpected zone list format"))
        return None
    return [
        z for z in data
        if isinstance(z, dict) and z.get("id") and z.get("name")
    ]


def select_zone(zones):
    """Let the user pick a zone by number or exact domain name."""
    global CURRENT_ZONE
    by_name = {str(z["name"]).strip().lower(): z for z in zones}
    while True:
        print_step(3)
        lines = []
        for index, zone in enumerate(zones, start=1):
            num = c(str(index) + ")", ANSI_BOLD_YELLOW)
            lines.append(num + " " + t("domain_label") + ": "
                         + c(str(zone["name"]), ANSI_BOLD_GREEN))
            lines.append("    " + t("zoneid_label") + ": "
                         + c(str(zone["id"]), ANSI_BOLD_CYAN))
            if index < len(zones):
                lines.append("")
        lines.append(c("0)", ANSI_DIM_WHITE) + " " + t("back_label"))
        lines.append(c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label"))
        box(t("zones_header"), lines,
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("prompt_zone")).strip()
        if _is_quit_token(raw):
            _quit()
        if _is_back_token(raw):
            _print_abort()
            return BACK
        if raw.isdigit():
            number = int(raw)
            if 1 <= number <= len(zones):
                chosen = zones[number - 1]
                CURRENT_ZONE = str(chosen["name"])
                print_ok(t("zone_selected").format(
                    name=chosen["name"], zone_id=chosen["id"]))
                return chosen
        lowered = raw.lower()
        if lowered in by_name:
            chosen = by_name[lowered]
            CURRENT_ZONE = str(chosen["name"])
            print_ok(t("zone_selected").format(
                name=chosen["name"], zone_id=chosen["id"]))
            return chosen
        print_error(t("zone_invalid"))


DIGEST_HEX_LEN = {1: 40, 2: 64, 3: 64, 4: 96}


def validate_ds(content):
    """Validate DS content.

    Returns None when valid, an error key when invalid, or the digest type
    (int) when valid but the digest length is unusual for that type.
    """
    parts = content.strip().split()
    if len(parts) != 4:
        return "ds_error_parts"
    try:
        key_tag, algorithm, digest_type = (int(p) for p in parts[:3])
    except ValueError:
        return "ds_error_ints"
    if not 0 <= key_tag <= 65535:
        return "ds_error_keytag"
    if not 0 <= algorithm <= 255:
        return "ds_error_algorithm"
    if digest_type not in (1, 2, 3, 4):
        return "ds_error_digesttype"
    digest = parts[3]
    if not digest or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
        return "ds_error_hex"
    expected = DIGEST_HEX_LEN.get(digest_type)
    if expected is not None and len(digest) != expected:
        return digest_type
    return None


def prompt_ds():
    """Prompt for DS content; bare 0 returns BACK, q is literal."""
    print_info(t("ds_example"))
    while True:
        raw = _prompt_input(t("prompt_ds")).strip()
        if _is_back_token(raw):
            return BACK
        result = validate_ds(raw)
        if result is None:
            return " ".join(raw.split())
        if isinstance(result, int):
            print_warn(t("ds_warn_length").format(
                digest_type=result, length=len(raw.split()[3]),
                expected=DIGEST_HEX_LEN.get(result)))
            return " ".join(raw.split())
        print_error(t(result))


def prompt_ttl(default=DEFAULT_TTL):
    """Prompt for TTL; empty input yields default, bare 0 returns BACK."""
    while True:
        raw = _prompt_input(t("prompt_ttl").format(default=default)).strip()
        if _is_back_token(raw):
            return BACK
        if raw == "":
            return default
        try:
            value = int(raw)
        except ValueError:
            print_error(t("ttl_invalid").format(default=default))
            continue
        if 1 <= value <= 2147483647:
            return value
        print_error(t("ttl_invalid").format(default=default))


def prompt_record_name(default_name):
    """Prompt for record name; empty keeps default, bare 0 returns BACK."""
    raw = _prompt_input(t("prompt_name").format(default=default_name)).strip()
    if _is_back_token(raw):
        return BACK
    if raw == "":
        return default_name
    return raw


def ask_confirm():
    """Ask confirmation; True/False, q/0 aborts. Empty input re-prompts."""
    while True:
        hint = _confirm_hint_q()
        raw = _prompt_input(
            t("prompt_confirm").format(hint=hint)).strip().lower()
        if raw in ("q", "0"):
            _print_abort()
            return BACK
        if is_yes(raw):
            return True
        if is_no(raw):
            return False
        print_error(t("confirm_invalid"))


def ask_confirm_for(prompt_key, **fmt_kwargs):
    """Ask a yes/no question; True/False, q/0 aborts (returns BACK)."""
    while True:
        hint = _confirm_hint_q()
        fmt_kwargs.setdefault("hint", hint)
        raw = _prompt_input(t(prompt_key).format(**fmt_kwargs)).strip().lower()
        if raw in ("q", "0"):
            _print_abort()
            return BACK
        if is_yes(raw):
            return True
        if is_no(raw):
            return False
        print_error(t("confirm_invalid"))


def update_ds_record(token, zone_id, record_id, content, ttl):
    """PUT new content/ttl onto a DS record; status or None on failure."""
    print_info(t("sending_update"))
    url = (
        ZONES_URL
        + "/"
        + urllib.parse.quote(str(zone_id), safe="")
        + "/records/"
        + urllib.parse.quote(str(record_id), safe="")
    )
    payload = {"content": content, "ttl": ttl, "prio": 0, "disabled": False}
    status, data = api_request("PUT", url, token, payload)
    if status is None:
        return None
    print_ok(t("update_ok").format(status=status))
    if isinstance(data, str) and data.strip():
        print_info(t("success_body").format(body=_shorten(data.strip())))
    elif data is not None:
        print_info(t("success_body").format(body=_shorten(json.dumps(data))))
    return status


def delete_record(token, zone_id, record_id):
    """DELETE a record; HTTP status or None on failure."""
    print_info(t("sending_delete"))
    url = (
        ZONES_URL
        + "/"
        + urllib.parse.quote(str(zone_id), safe="")
        + "/records/"
        + urllib.parse.quote(str(record_id), safe="")
    )
    status, data = api_request("DELETE", url, token)
    if status is None:
        return None
    print_ok(t("delete_ok").format(status=status))
    if isinstance(data, str) and data.strip():
        print_info(t("success_body").format(body=_shorten(data.strip())))
    elif data is not None:
        print_info(t("success_body").format(body=_shorten(json.dumps(data))))
    return status


def display_ds_records(records):
    """Print DS records as a table; content truncated for display."""
    header = "{n} | {rid} | {c} | {ttl}".format(
        n=t("th_n"), rid=t("th_id"), c=t("th_content"), ttl=t("th_ttl"))
    header_colored = c(header, ANSI_BOLD_CYAN)
    rows = []
    for index, record in enumerate(records, start=1):
        rows.append(_ds_row(
            index, record.get("id", "?"), record.get("content", "?"),
            record.get("ttl", "?")))
    box(t("existing_ds"), [header_colored] + rows,
        footer_lines=[t("truncation_note")],
        border_color=ANSI_WHITE, title_color=ANSI_WHITE)


def prompt_ds_action():
    """Ask the DS action; returns update/create/delete or BACK."""
    compat_update = ("u", "update", "a", "aktualisieren")
    compat_create = ("c", "create", "erstellen", "crear")
    compat_delete = ("d", "delete", "loeschen", "eliminar")
    while True:
        l1 = c("1)", ANSI_BOLD_YELLOW) + " " + t("option_update")
        l2 = c("2)", ANSI_BOLD_YELLOW) + " " + t("option_create")
        l3 = c("3)", ANSI_BOLD_YELLOW) + " " + t("option_delete")
        l0 = c("0)", ANSI_DIM_WHITE) + " " + t("back_label")
        l9 = c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label")
        box(t("action_menu_title"), [l1, l2, l3, l0, l9],
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("choose_action")).strip().lower()
        if _is_quit_token(raw):
            _quit()
        if _is_back_token(raw):
            return BACK
        if raw == "1" or raw in compat_update:
            return "update"
        if raw == "2" or raw in compat_create:
            return "create"
        if raw == "3" or raw in compat_delete:
            return "delete"
        if raw == "l" + chr(246) + "schen":
            return "delete"
        print_error(t("action_invalid"))


def select_ds_record(records):
    """Return the chosen record; auto-select when only one exists."""
    if len(records) == 1:
        record = records[0]
        print_info(t("auto_selected").format(id=record.get("id", "?")))
        return record
    count = len(records)
    while True:
        header = (
            f"{t('th_n')} | {t('th_id')} | "
            f"{t('th_content')} | {t('th_ttl')}"
        )
        lines = [c(header, ANSI_BOLD_CYAN)]
        for index, record in enumerate(records, start=1):
            num = c(str(index) + ")", ANSI_BOLD_YELLOW)
            row = _ds_row(
                index, record.get("id", "?"), record.get("content", "?"),
                record.get("ttl", "?"))
            tail = row.split("|", 1)[1] if "|" in row else ""
            lines.append(num + " |" + tail)
        lines.append(c("0)", ANSI_DIM_WHITE) + " " + t("back_label"))
        lines.append(c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label"))
        box(t("record_menu_title"), lines,
            footer_lines=[t("truncation_note")],
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("select_record")).strip()
        if _is_quit_token(raw):
            _quit()
        if _is_back_token(raw):
            _print_abort()
            return BACK
        if raw.isdigit():
            number = int(raw)
            if 1 <= number <= count:
                return records[number - 1]
        print_error(t("record_invalid").format(count=count))


def default_ttl_of(record):
    """TTL default from a record, else DEFAULT_TTL."""
    try:
        value = int(record.get("ttl", DEFAULT_TTL))
    except (TypeError, ValueError):
        return DEFAULT_TTL
    if 1 <= value <= 2147483647:
        return value
    return DEFAULT_TTL


def handle_update_flow(token, zone_id, records):
    """Prompt new DS/TTL, confirm, PUT. True/False/BACK."""
    target = select_ds_record(records)
    if not isinstance(target, dict):
        return BACK
    old_content = str(target.get("content", ""))
    old_ttl = default_ttl_of(target)
    new_content = prompt_ds()
    if new_content is BACK:
        _print_abort()
        return BACK
    new_ttl = prompt_ttl(default=old_ttl)
    if new_ttl is BACK:
        _print_abort()
        return BACK
    old_line = c(
        t("diff_current").format(content=old_content, ttl=old_ttl), ANSI_RED)
    new_line = c(
        t("diff_new").format(content=new_content, ttl=new_ttl), ANSI_GREEN)
    box(t("option_update"), [old_line, new_line],
        border_color=ANSI_WHITE, title_color=ANSI_WHITE)
    answer = ask_confirm_for("confirm_update")
    if answer is BACK:
        return BACK
    if not answer:
        print_info(t("cancelled"))
        return False
    return update_ds_record(
        token, zone_id, target.get("id"), new_content, new_ttl) is not None


def handle_delete_flow(token, zone_id, records):
    """Double-confirm then DELETE. True/False/BACK."""
    target = select_ds_record(records)
    if not isinstance(target, dict):
        return BACK
    record_id = target.get("id")
    first = ask_confirm_for("confirm_delete", id=record_id)
    if first is BACK:
        return BACK
    if not first:
        print_info(t("cancelled"))
        return False
    second = ask_confirm_for("confirm_delete_again")
    if second is BACK:
        return BACK
    if not second:
        print_info(t("cancelled"))
        return False
    return delete_record(token, zone_id, record_id) is not None


def handle_create_flow(token, zone_id, domain):
    """Prompt DS/TTL/name, then POST. BACK aborts."""
    ds_content = prompt_ds()
    if ds_content is BACK:
        _print_abort()
        return BACK
    ttl = prompt_ttl()
    if ttl is BACK:
        _print_abort()
        return BACK
    record_name = prompt_record_name(domain)
    if record_name is BACK:
        _print_abort()
        return BACK
    return post_ds(zone_id, record_name, ds_content, ttl, token)


def post_ds(zone_id, record_name, ds_content, ttl, token):
    """Show summary, confirm and POST. True/False/BACK."""
    box(t("summary_title"), [
        t("summary_zone").format(zone_id=zone_id),
        t("summary_record_name").format(name=record_name),
        t("summary_type"),
        t("summary_content").format(content=ds_content),
        t("summary_ttl").format(ttl=ttl),
    ], border_color=ANSI_WHITE, title_color=ANSI_WHITE)
    answer = ask_confirm()
    if answer is BACK:
        return BACK
    if not answer:
        print_info(t("cancelled"))
        return False

    print_info(t("sending"))
    url = (
        ZONES_URL + "/" + urllib.parse.quote(str(zone_id), safe="")
        + "/records"
    )
    payload = [
        {
            "name": record_name,
            "type": "DS",
            "content": ds_content,
            "ttl": ttl,
            "prio": 0,
            "disabled": False,
        }
    ]
    status, data = api_request("POST", url, token, payload)
    if status is None:
        return False
    print_ok(t("success").format(status=status))
    if isinstance(data, str) and data.strip():
        print_info(t("success_body").format(body=_shorten(data.strip())))
    elif data is not None:
        print_info(t("success_body").format(body=_shorten(json.dumps(data))))
    return True


def prompt_next_action():
    """Offer retry/other/quit; returns retry/other/BACK."""
    while True:
        l1 = c("1)", ANSI_BOLD_YELLOW) + " " + t("menu_retry")
        l2 = c("2)", ANSI_BOLD_YELLOW) + " " + t("menu_other")
        l0 = c("0)", ANSI_DIM_WHITE) + " " + t("back_label")
        l9 = c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label")
        box(t("menu_title"), [l1, l2, l0, l9],
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("prompt_menu")).strip().lower()
        if raw in ("9", "q", "3"):
            _quit()
        if raw == "0":
            return BACK
        if raw == "1":
            return "retry"
        if raw == "2":
            return "other"
        print_error(t("menu_invalid"))


def prompt_fetch_retry():
    """Ask retry/back/quit after a failed fetch; True/BACK."""
    while True:
        print_error(t("fetch_retry"))
        l1 = c("1)", ANSI_BOLD_YELLOW) + " " + t("option_retry")
        l2 = c("2)", ANSI_BOLD_YELLOW) + " " + t("option_quit")
        l0 = c("0)", ANSI_DIM_WHITE) + " " + t("back_label")
        l9 = c("9)", ANSI_BOLD_MAGENTA) + " " + t("quit_label")
        box(t("fetch_retry"), [l1, l2, l0, l9],
            border_color=ANSI_WHITE, title_color=ANSI_WHITE)
        raw = _prompt_input(t("prompt_choice_2")).strip().lower()
        if raw in ("9", "q"):
            _quit()
        if raw == "0":
            _print_abort()
            return BACK
        if raw == "1":
            return True
        if raw == "2":
            _quit()
        if raw in ("r", "w"):
            return True
        if raw in ("s", "b"):
            _quit()
        if is_yes(raw):
            return True
        if is_no(raw):
            _quit()
        print_error(t("fetch_retry_invalid"))


def _clear_context():
    """Reset the key/zone context shown in step headers."""
    global CURRENT_MASKED, CURRENT_ZONE
    CURRENT_MASKED = "--"
    CURRENT_ZONE = "--"


def _clear_zone():
    """Reset only the zone context; the API key stays active."""
    global CURRENT_ZONE
    CURRENT_ZONE = "--"


def _placeholders(text):
    """Return the set of format placeholder names in a string."""
    return {
        name for _, name, _, _ in string.Formatter().parse(str(text))
        if name
    }


def self_test():
    """Run offline self-checks; return 0 when everything passes."""
    global LANG
    failures = []

    def check(name, condition):
        if condition:
            print_ok(f"self-test: {name}")
        else:
            failures.append(name)
            print_error(f"self-test: {name}")

    check("languages en/es/de", set(STRINGS) == {"en", "es", "de"})
    check("i18n key parity",
          len({frozenset(table) for table in STRINGS.values()}) == 1)
    base = STRINGS["en"]
    check("i18n placeholder parity", all(
        _placeholders(base[key]) == _placeholders(STRINGS[lang][key])
        for key in base for lang in STRINGS))

    valid_ds = "12345 13 2 " + "A" * 64
    check("validate_ds accepts valid", validate_ds(valid_ds) is None)
    check("validate_ds rejects parts",
          validate_ds("1 2 3") == "ds_error_parts")
    check("validate_ds rejects keyTag",
          validate_ds("70000 13 2 " + "A" * 64) == "ds_error_keytag")
    check("validate_ds rejects algorithm",
          validate_ds("1 300 2 " + "A" * 64) == "ds_error_algorithm")
    check("validate_ds rejects digestType",
          validate_ds("1 13 9 " + "A" * 64) == "ds_error_digesttype")
    check("validate_ds warns on odd length",
          validate_ds("1 13 2 " + "A" * 20) == 2)

    secret = "s" * 40
    masked = mask_token("publictoken." + secret)
    check("mask hides the secret",
          secret not in masked and masked.endswith("****"))
    check("mask never shows secret for short public",
          mask_token("a." + secret) == "a****")

    check("box width is 68", _visible_len(_box_border("")) == BOX_FILL + 2)

    saved = LANG
    try:
        LANG = "en"
        check("confirm tokens en",
              is_yes("y") and is_yes("yes") and is_no("n"))
        LANG = "es"
        check("confirm tokens es",
              is_yes("s") and is_yes("sí") and is_no("no"))
        LANG = "de"
        check("confirm tokens de",
              is_yes("j") and is_yes("ja") and is_no("nein"))
    finally:
        LANG = saved

    if failures:
        print_error(f"self-test failed: {len(failures)} check(s)")
        return 1
    print_ok("self-test passed")
    return 0


def fetch_zones_with_retry(token):
    """Fetch zones offering retry; BACK when the user returns to the key."""
    zones = list_zones(token)
    while zones is None:
        if prompt_fetch_retry() is BACK:
            return BACK
        zones = list_zones(token)
    return zones


def run_ds_loop(token, zone_id, domain):
    """Handle DS records for one zone; returns 'other' to pick another zone."""
    while True:
        print_step(4)
        ds_records = list_ds_records(token, zone_id)
        if ds_records is None:
            # The error is already shown; go back instead of assuming "no DS"
            # (assuming empty could offer the create path and duplicate a DS).
            return "other"
        if not ds_records:
            print_info(t("no_ds"))
            if handle_create_flow(token, zone_id, domain) is BACK:
                return "other"
        else:
            display_ds_records(ds_records)
            print_warn(t("conflict_warning"))
            choice = prompt_ds_action()
            if choice is BACK:
                return "other"
            if choice == "update":
                result = handle_update_flow(token, zone_id, ds_records)
            elif choice == "create":
                result = handle_create_flow(token, zone_id, domain)
            else:
                result = handle_delete_flow(token, zone_id, ds_records)
            if result is BACK:
                continue
        action = prompt_next_action()
        if action is BACK or action == "retry":
            continue
        return "other"


def run_zone_loop(token, zones):
    """Pick zones and act on them until the user goes back to the key."""
    global CURRENT_ZONE
    while True:
        zone = select_zone(zones)
        if not isinstance(zone, dict):
            _clear_context()
            return
        CURRENT_ZONE = str(zone["name"])
        run_ds_loop(token, zone["id"], zone["name"])
        _clear_zone()


def build_parser():
    """Build the argparse CLI parser."""
    parser = argparse.ArgumentParser(
        prog="ionos_dnssec.py",
        description=(
            "Interactive IONOS DNSSEC DS manager (single file, stdlib only). "
            "Walks through Language, API key, zone selection and DS records "
            "with boxed ASCII layout (width 68) and "
            "0=Back 9/q=Quit navigation. "
            "To disable colors use --no-color "
            "(a bare NO_COLOR env var is ignored)."
        ),
        epilog=(
            "Examples: python3 ionos_dnssec.py --lang en | "
            "IONOS_COLOR=never python3 ionos_dnssec.py | "
            "python3 ionos_dnssec.py --color=always --lang de"
        ),
    )
    parser.add_argument("--lang", choices=["en", "es", "de"], default=None,
                        help="skip step 1 and use this language")
    parser.add_argument(
        "--color", choices=["always", "auto", "never"], default=None,
        help="color mode (default auto: colors ON when on a TTY)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI colors (same as --color=never)")
    parser.add_argument(
        "--no-clear", action="store_true",
        help="do not clear the screen on menu jumps "
             "(same as IONOS_NO_CLEAR=1)")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline self-checks and exit")
    parser.add_argument("--version", action="version",
                        version=f"%(prog)s {APP_VERSION}")
    return parser


def main(argv=None):
    """Run the interactive language, key, zone and DS flow."""
    global LANG, CLEAR_ENABLED
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_color(cli_color=args.color, cli_no_color=args.no_color)
    CLEAR_ENABLED = not args.no_clear

    if args.self_test:
        return self_test()

    try:
        print_header()
        if args.lang is not None:
            LANG = args.lang
        else:
            choose_language()
        print_info(t("welcome"))
        print_info(t("api_info"))
        print_info(t("key_format"))

        while True:
            token = get_api_token()
            if token is BACK:
                if args.lang is None:
                    choose_language()
                _clear_context()
                continue
            zones = fetch_zones_with_retry(token)
            if zones is BACK:
                _clear_context()
                continue
            if not zones:
                print_error(t("zones_empty"))
                print(t("goodbye"))
                return 0
            run_zone_loop(token, zones)
            _clear_context()
    except (KeyboardInterrupt, EOFError):
        print(t("interrupted"))
        return 130


if __name__ == "__main__":
    sys.exit(main())
