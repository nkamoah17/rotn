package com.rot.n.scheduler;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal JSON parser for the flat schedule records (objects, arrays,
 *  strings with escapes, integers, true/false/null). No external libs.
 *  Throws GateException on malformed input.
 */
final class JsonLine {

    private final String s;
    private int i;

    private JsonLine(String s) {
        this.s = s;
        this.i = 0;
    }

    static Object parse(String text) {
        JsonLine p = new JsonLine(text);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != p.s.length()) {
            throw new GateException("trailing characters at offset " + p.i);
        }
        return v;
    }

    private Object value() {
        if (i >= s.length()) {
            throw new GateException("unexpected end of input");
        }
        char c = s.charAt(i);
        if (c == '{') {
            return object();
        }
        if (c == '[') {
            return array();
        }
        if (c == '"') {
            return string();
        }
        if (c == 't' || c == 'f' || c == 'n') {
            return literal();
        }
        return number();
    }

    private Map<String, Object> object() {
        Map<String, Object> m = new LinkedHashMap<String, Object>();
        i++; // {
        ws();
        if (peek() == '}') {
            i++;
            return m;
        }
        while (true) {
            ws();
            if (peek() != '"') {
                throw new GateException("expected object key at offset " + i);
            }
            String key = string();
            ws();
            if (peek() != ':') {
                throw new GateException("expected ':' at offset " + i);
            }
            i++;
            ws();
            m.put(key, value());
            ws();
            char c = peek();
            if (c == ',') {
                i++;
                continue;
            }
            if (c == '}') {
                i++;
                return m;
            }
            throw new GateException("expected ',' or '}' at offset " + i);
        }
    }

    private List<Object> array() {
        List<Object> l = new ArrayList<Object>();
        i++; // [
        ws();
        if (peek() == ']') {
            i++;
            return l;
        }
        while (true) {
            ws();
            l.add(value());
            ws();
            char c = peek();
            if (c == ',') {
                i++;
                continue;
            }
            if (c == ']') {
                i++;
                return l;
            }
            throw new GateException("expected ',' or ']' at offset " + i);
        }
    }

    private String string() {
        StringBuilder b = new StringBuilder();
        i++; // opening quote
        while (true) {
            if (i >= s.length()) {
                throw new GateException("unterminated string");
            }
            char c = s.charAt(i++);
            if (c == '"') {
                return b.toString();
            }
            if (c == '\\') {
                if (i >= s.length()) {
                    throw new GateException("bad escape");
                }
                char e = s.charAt(i++);
                switch (e) {
                    case '"': b.append('"'); break;
                    case '\\': b.append('\\'); break;
                    case '/': b.append('/'); break;
                    case 'n': b.append('\n'); break;
                    case 'r': b.append('\r'); break;
                    case 't': b.append('\t'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'u':
                        if (i + 4 > s.length()) {
                            throw new GateException("bad \\u escape");
                        }
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default:
                        throw new GateException("bad escape \\" + e);
                }
            } else {
                b.append(c);
            }
        }
    }

    private Object literal() {
        if (s.startsWith("true", i)) {
            i += 4;
            return Boolean.TRUE;
        }
        if (s.startsWith("false", i)) {
            i += 5;
            return Boolean.FALSE;
        }
        if (s.startsWith("null", i)) {
            i += 4;
            return null;
        }
        throw new GateException("bad literal at offset " + i);
    }

    private Object number() {
        int start = i;
        if (peek() == '-') {
            i++;
        }
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9' || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                i++;
            } else {
                break;
            }
        }
        String tok = s.substring(start, i);
        if (tok.length() == 0) {
            throw new GateException("expected value at offset " + start);
        }
        try {
            return Long.parseLong(tok);
        } catch (NumberFormatException exc) {
            // schedule contract only uses integers; keep raw text as fallback
            return tok;
        }
    }

    private char peek() {
        if (i >= s.length()) {
            throw new GateException("unexpected end of input");
        }
        return s.charAt(i);
    }

    private void ws() {
        while (i < s.length()) {
            char c = s.charAt(i);
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                i++;
            } else {
                break;
            }
        }
    }
}
