package org.qypp.f5;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class F5ReportParser {
    private F5ReportParser() {
    }

    public static F5Report parse(String json) {
        return new F5Report(
                stringValue(json, "label"),
                stringValue(json, "target_type", "f5"),
                stringValue(json, "hostname"),
                stringValue(json, "collected_at"),
                stringValue(json, "status"),
                stringValue(json, "privilege_mode", "login-user"),
                booleanValue(json, "privileged_collection"),
                stringValue(json, "os"),
                stringValue(json, "uptime"),
                intValue(json, "process_count"),
                longValue(json, "cpu_core_count"),
                longValue(json, "cpu_load_percent"),
                doubleValue(json, "load_average_1m"),
                doubleValue(json, "load_average_5m"),
                doubleValue(json, "load_average_15m"),
                longValue(json, "load_average_1m_percent"),
                longValue(json, "load_average_5m_percent"),
                longValue(json, "load_average_15m_percent"),
                longValue(json, "disk_used_percent"),
                intValue(json, "service_count"),
                intValue(json, "listener_count"),
                longValue(json, "memory_used_kb"),
                longValue(json, "memory_total_kb"),
                stringArray(json, "disk_mounts"),
                longValue(json, "ip_connection_count"),
                longValue(json, "ip_connection_max"),
                stringArray(json, "active_connections"),
                stringArray(json, "critical_services_down"),
                intArray(json, "external_listening_ports"),
                stringArray(json, "listening_endpoints"),
                stringArray(json, "processes_by_cpu"),
                stringArray(json, "processes_by_memory"),
                stringArray(json, "running_services"),
                stringArray(json, "network_interfaces"),
                stringArray(json, "system_users"),
                stringArray(json, "logged_users"),
                stringArray(json, "f5_load_history"),
                stringArray(json, "f5_partitions_pools"),
                stringArray(json, "outbound_checks"),
                stringArray(json, "recent_log_errors"),
                checks(json)
        );
    }

    private static String stringValue(String json, String key) {
        return stringValue(json, key, "");
    }

    private static String stringValue(String json, String key, String defaultValue) {
        int keyStart = jsonStringIndex(json, key, 0);
        while (keyStart >= 0) {
            int afterKey = keyStart + key.length() + 2;
            int colon = skipWhitespace(json, afterKey);
            if (colon < json.length() && json.charAt(colon) == ':') {
                int valueStart = skipWhitespace(json, colon + 1);
                if (valueStart < json.length() && json.charAt(valueStart) == '"') {
                    String value = readJsonString(json, valueStart);
                    return value == null ? defaultValue : unescape(value);
                }
            }
            keyStart = jsonStringIndex(json, key, afterKey);
        }
        return defaultValue;
    }

    private static int intValue(String json, String key) {
        return (int) longValue(json, key);
    }

    private static long longValue(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+)").matcher(json);
        return matcher.find() ? Long.parseLong(matcher.group(1)) : 0;
    }

    private static boolean booleanValue(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(true|false)").matcher(json);
        return matcher.find() && Boolean.parseBoolean(matcher.group(1));
    }

    private static double doubleValue(String json, String key) {
        Matcher matcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*(-?\\d+(?:\\.\\d+)?)").matcher(json);
        return matcher.find() ? Double.parseDouble(matcher.group(1)) : 0;
    }

    private static List<String> stringArray(String json, String key) {
        String body = arrayBody(json, key);
        List<String> values = new ArrayList<>();
        boolean inString = false;
        boolean escaped = false;
        StringBuilder current = new StringBuilder();
        for (int i = 0; i < body.length(); i++) {
            char character = body.charAt(i);
            if (!inString) {
                if (character == '"') {
                    inString = true;
                    current.setLength(0);
                }
                continue;
            }
            if (escaped) {
                current.append('\\').append(character);
                escaped = false;
                continue;
            }
            if (character == '\\') {
                escaped = true;
                continue;
            }
            if (character == '"') {
                values.add(unescape(current.toString()));
                inString = false;
                continue;
            }
            current.append(character);
        }
        return values;
    }

    private static List<Integer> intArray(String json, String key) {
        String body = arrayBody(json, key);
        List<Integer> values = new ArrayList<>();
        Matcher matcher = Pattern.compile("-?\\d+").matcher(body);
        while (matcher.find()) {
            values.add(Integer.parseInt(matcher.group()));
        }
        return values;
    }

    private static List<F5Check> checks(String json) {
        String body = arrayBody(json, "checks");
        List<F5Check> checks = new ArrayList<>();
        for (String object : objectBodies(body)) {
            checks.add(new F5Check(
                    stringValue(object, "name"),
                    stringValue(object, "status"),
                    stringValue(object, "detail")
            ));
        }
        return checks;
    }

    private static List<String> objectBodies(String body) {
        List<String> objects = new ArrayList<>();
        int depth = 0;
        int start = -1;
        boolean inString = false;
        boolean escaped = false;
        for (int i = 0; i < body.length(); i++) {
            char current = body.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (current == '\\') {
                escaped = true;
                continue;
            }
            if (current == '"') {
                inString = !inString;
                continue;
            }
            if (inString) {
                continue;
            }
            if (current == '{') {
                if (depth == 0) {
                    start = i + 1;
                }
                depth++;
            } else if (current == '}') {
                depth--;
                if (depth == 0 && start >= 0) {
                    objects.add(body.substring(start, i));
                    start = -1;
                }
            }
        }
        return objects;
    }

    private static String arrayBody(String json, String key) {
        Matcher keyMatcher = Pattern.compile("\"" + Pattern.quote(key) + "\"\\s*:\\s*\\[").matcher(json);
        if (!keyMatcher.find()) {
            return "";
        }
        int start = keyMatcher.end();
        int depth = 1;
        boolean inString = false;
        boolean escaped = false;
        for (int i = start; i < json.length(); i++) {
            char current = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (current == '\\') {
                escaped = true;
                continue;
            }
            if (current == '"') {
                inString = !inString;
                continue;
            }
            if (!inString && current == '[') {
                depth++;
            } else if (!inString && current == ']') {
                depth--;
                if (depth == 0) {
                    return json.substring(start, i);
                }
            }
        }
        return "";
    }

    private static int jsonStringIndex(String json, String value, int fromIndex) {
        for (int i = Math.max(0, fromIndex); i < json.length(); i++) {
            if (json.charAt(i) != '"') {
                continue;
            }
            String candidate = readJsonString(json, i);
            if (value.equals(candidate)) {
                return i;
            }
            i = skipJsonString(json, i);
        }
        return -1;
    }

    private static int skipWhitespace(String json, int index) {
        int current = index;
        while (current < json.length() && Character.isWhitespace(json.charAt(current))) {
            current++;
        }
        return current;
    }

    private static String readJsonString(String json, int quoteIndex) {
        StringBuilder value = new StringBuilder();
        boolean escaped = false;
        for (int i = quoteIndex + 1; i < json.length(); i++) {
            char current = json.charAt(i);
            if (escaped) {
                value.append('\\').append(current);
                escaped = false;
                continue;
            }
            if (current == '\\') {
                escaped = true;
                continue;
            }
            if (current == '"') {
                return value.toString();
            }
            value.append(current);
        }
        return null;
    }

    private static int skipJsonString(String json, int quoteIndex) {
        boolean escaped = false;
        for (int i = quoteIndex + 1; i < json.length(); i++) {
            char current = json.charAt(i);
            if (escaped) {
                escaped = false;
                continue;
            }
            if (current == '\\') {
                escaped = true;
                continue;
            }
            if (current == '"') {
                return i;
            }
        }
        return json.length() - 1;
    }

    private static String unescape(String text) {
        return text.replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .replace("\\n", "\n")
                .replace("\\r", "\r")
                .replace("\\t", "\t");
    }
}
