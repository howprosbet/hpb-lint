#!/usr/bin/env python3
"""HowProsBet deterministic linter v0.2.5.

Implements the mechanical rules defined in HPB_LINT.md as of 2026-08-12.
No network access. Explicit v0.2.4 CLI inputs remain supported. With no arguments,
v0.2.5 auto-discovers the standard sitewide WXR, inventory, roles, config and Green baseline.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, asdict
from email.utils import parsedate_to_datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Optional
from urllib.parse import urljoin, urlparse, urlunparse

import tinycss2
from lxml import html as lxml_html

VERSION = "0.2.5"
SEVERITY_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}
VOID_HTML = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr"
}
FILE_EXT_RE = re.compile(r"\.[a-z0-9]{1,8}$", re.I)
CURACAO_RE = re.compile(r"\bCura(?:çao|cao)\b", re.I)
CLASS_RE = re.compile(r"\.([_a-zA-Z][-_a-zA-Z0-9]*)")
WP_OPEN_RE = re.compile(r"<!--\s*wp:([\w/-]+)(?:\s+.*?)?-->", re.S)
WP_CLOSE_RE = re.compile(r"<!--\s*/wp:([\w/-]+)\s*-->", re.S)
WP_TOKEN_RE = re.compile(
    r"<!--\s*(?:(wp:([\w/-]+)(?:\s+.*?)?)|(/wp:([\w/-]+)))\s*(/)?-->", re.S
)
SUPPRESS_CSS_RE = re.compile(
    r"^\s*/\*\s*hpb-lint-disable-next-line\s+(HPB-[A-Z0-9-]+)\s+(.+?)\s*\*/\s*$"
)
SUPPRESS_HTML_RE = re.compile(
    r"^\s*<!--\s*hpb-lint-disable-next-line\s+(HPB-[A-Z0-9-]+)\s+(.+?)\s*-->\s*$"
)


@dataclass
class Finding:
    rule_id: str
    severity: str
    line: int
    message: str
    excerpt: str = ""
    source: str = ""

    def key(self):
        return (SEVERITY_ORDER.get(self.severity, 9), self.line, self.rule_id, self.message)


class BalanceParser(HTMLParser):
    """Explicit-balance checker using Python's HTML parser, SVG-aware by design.

    SVG elements are not treated as HTML void elements. Custom HTML is expected
    to use explicit closing tags even where HTML technically permits omission.
    """

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, int]] = []
        self.errors: list[tuple[int, str]] = []

    def handle_starttag(self, tag: str, attrs):
        tag = tag.lower()
        if tag not in VOID_HTML:
            self.stack.append((tag, self.getpos()[0]))

    def handle_startendtag(self, tag: str, attrs):
        pass

    def handle_endtag(self, tag: str):
        tag = tag.lower()
        line = self.getpos()[0]
        if tag in VOID_HTML:
            return
        if not self.stack:
            self.errors.append((line, f"closing </{tag}> without matching opener"))
            return
        top, top_line = self.stack[-1]
        if top == tag:
            self.stack.pop()
            return
        # Misnesting is an error. Pop matching tag if present to avoid cascades.
        names = [x[0] for x in self.stack]
        if tag in names:
            self.errors.append((line, f"misnested </{tag}>; open <{top}> from line {top_line} is still active"))
            while self.stack:
                name, _ = self.stack.pop()
                if name == tag:
                    break
        else:
            self.errors.append((line, f"closing </{tag}> without matching opener"))

    def finish(self):
        for tag, line in reversed(self.stack):
            self.errors.append((line, f"unclosed <{tag}>") )
        self.stack.clear()


def load_json(path: Optional[str], default: Any = None) -> Any:
    if not path:
        return default
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_excerpt(text: str, line: int, maxlen: int = 180) -> str:
    lines = text.splitlines()
    if 1 <= line <= len(lines):
        s = lines[line - 1].strip()
        return s if len(s) <= maxlen else s[: maxlen - 1] + "…"
    return ""


def suppression_for(text: str, line: int, rule_id: str, config: dict) -> bool:
    if rule_id in set(config.get("non_suppressable_rules", [])):
        return False
    if line <= 1:
        return False
    prev = text.splitlines()[line - 2]
    m = SUPPRESS_CSS_RE.match(prev) or SUPPRESS_HTML_RE.match(prev)
    return bool(m and m.group(1) == rule_id and m.group(2).strip())


def add_finding(findings: list[Finding], finding: Finding, text: str, config: dict):
    if suppression_for(text, finding.line, finding.rule_id, config):
        return
    if not finding.excerpt:
        finding.excerpt = line_excerpt(text, finding.line)
    findings.append(finding)


def parse_inventory(path: Optional[str]) -> Optional[set[str]]:
    if not path:
        return None
    urls: set[str] = set()
    with open(path, encoding="utf-8-sig", newline="") as f:
        r = csv.DictReader(f)
        for row in r:
            addr = row.get("Adresse") or row.get("Address")
            status = row.get("Status-Code") or row.get("Status Code")
            if addr and str(status).strip() == "200":
                urls.add(addr.strip())
    return urls


def load_roles(path: Optional[str]) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    data = load_json(path, {})
    return data.get("roles", data)


def normalize_internal_href(href: str, origin: str) -> Optional[str]:
    href = href.strip()
    if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
        return None
    absolute = urljoin(origin + "/", href)
    p = urlparse(absolute)
    if p.hostname and p.hostname.lower() == urlparse(origin).hostname.lower():
        # For inventory comparison ignore fragment, preserve query because it can be a real distinct URL.
        return urlunparse(("https", p.hostname.lower(), p.path or "/", "", "", ""))
    return None


def html_blocks(text: str) -> list[tuple[int, int, str]]:
    """Return content ranges for wp:html blocks as offsets and string."""
    blocks: list[tuple[int, int, str]] = []
    stack: list[tuple[str, int, int]] = []
    for m in WP_TOKEN_RE.finditer(text):
        if m.group(2):
            name = m.group(2)
            selfclosing = bool(m.group(5))
            if not selfclosing:
                stack.append((name, m.end(), m.start()))
        else:
            name = m.group(4)
            if stack and stack[-1][0] == name:
                open_name, content_start, opener_start = stack.pop()
                if name == "html":
                    blocks.append((content_start, m.start(), text[content_start:m.start()]))
    return blocks


def lxml_document(text: str):
    parser = lxml_html.HTMLParser(encoding="utf-8", recover=True)
    try:
        return lxml_html.fromstring(text, parser=parser)
    except Exception:
        return lxml_html.fragment_fromstring(text, create_parent="div", parser=parser)


def extract_text(root) -> str:
    # Exclude script/style payloads and HTML comments from text-scope rules.
    # HPB "text" scope means visible text nodes, not code/comments/attributes.
    for bad in root.xpath("//script|//style"):
        bad.drop_tree()
    for comment in root.xpath("//comment()"):
        parent = comment.getparent()
        if parent is not None:
            parent.remove(comment)
    return " ".join(t.strip() for t in root.itertext() if t and t.strip())


def recursive_schema_types(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        if "@type" in obj:
            t = obj["@type"]
            if isinstance(t, str):
                found.append(t)
            elif isinstance(t, list):
                found.extend(str(x) for x in t)
        for v in obj.values():
            found.extend(recursive_schema_types(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(recursive_schema_types(v))
    return found


def lint_html(text: str, source: str, target_url: Optional[str], config: dict,
              inventory: Optional[set[str]], roles: dict[str, dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    origin = config["site_origin"]

    # HPB-WP-001: Gutenberg block stack.
    stack: list[tuple[str, int]] = []
    for m in WP_TOKEN_RE.finditer(text):
        line = line_of(text, m.start())
        if m.group(2):
            name = m.group(2)
            if not m.group(5):
                stack.append((name, line))
        else:
            name = m.group(4)
            if not stack:
                add_finding(findings, Finding("HPB-WP-001", "ERROR", line,
                    f"closing WordPress block /wp:{name} has no matching opener", source=source), text, config)
            elif stack[-1][0] != name:
                top_name, top_line = stack[-1]
                add_finding(findings, Finding("HPB-WP-001", "ERROR", line,
                    f"closing /wp:{name} mismatches open wp:{top_name} from line {top_line}", source=source), text, config)
            else:
                stack.pop()
    for name, line in stack:
        add_finding(findings, Finding("HPB-WP-001", "ERROR", line,
            f"open WordPress block wp:{name} is never closed", source=source), text, config)

    # HPB-WP-006: explicit balance inside each custom HTML block.
    for start, end, block in html_blocks(text):
        bp = BalanceParser()
        try:
            bp.feed(block)
            bp.close()
            bp.finish()
            base_line = line_of(text, start) - 1
            for local_line, msg in bp.errors:
                line = base_line + local_line
                add_finding(findings, Finding("HPB-WP-006", "ERROR", line, msg, source=source), text, config)
        except Exception as e:
            line = line_of(text, start)
            add_finding(findings, Finding("HPB-WP-006", "ERROR", line,
                f"HTML parser error in wp:html block: {e}", source=source), text, config)

    root = lxml_document(text)

    # HPB-CSS-001 on content class tokens. The canonical denylist applies to
    # article/page markup as well as stylesheet selectors. v0.2.2 only enforced
    # it in CSS, which allowed removed global classes to survive silently in two
    # articles after A1 removed their styling.
    legacy_exact_html = set(config.get("legacy_exact_tokens", []))
    legacy_fams_html = [re.compile(x) for x in config.get("legacy_family_patterns", [])]
    for el in root.xpath('//*[@class]'):
        for token in (el.get("class") or "").split():
            if token in legacy_exact_html or any(pat.search(token) for pat in legacy_fams_html):
                add_finding(findings, Finding("HPB-CSS-001", "ERROR", int(getattr(el, "sourceline", None) or 1),
                    f"forbidden legacy class .{token} in content HTML", source=source), text, config)

    # Build approximate element-line helpers. lxml gives sourceline on parsed input.
    def el_line(el) -> int:
        return int(getattr(el, "sourceline", None) or 1)

    # HPB-WP-002 scripts + WP-009 JSON-LD.
    for el in root.xpath("//script"):
        line = el_line(el)
        typ = (el.get("type") or "").strip().lower()
        if typ != "application/ld+json":
            add_finding(findings, Finding("HPB-WP-002", "ERROR", line,
                "executable <script> found in content", source=source), text, config)
            continue
        payload = el.text or ""
        try:
            obj = json.loads(payload)
            types = recursive_schema_types(obj)
        except Exception as e:
            add_finding(findings, Finding("HPB-WP-009", "ERROR", line,
                f"invalid JSON-LD: {e}", source=source), text, config)
            continue
        if "FAQPage" in types:
            sev, msg = "ERROR", "FAQPage JSON-LD must not be injected in content HTML"
        elif target_url == config.get("start_here_url") and config.get("allowed_start_here_schema") in types:
            sev = None
        else:
            sev, msg = "WARN", f"unapproved inline schema: {', '.join(types) if types else 'unknown @type'}"
        if sev:
            add_finding(findings, Finding("HPB-WP-009", sev, line, msg, source=source), text, config)

    # HPB-WP-003 local styles. Work from raw wp:html blocks to preserve block boundary.
    start_here_exception = target_url == config.get("start_here_url") and re.search(r'class=["\'][^"\']*\bhpb-sh(?:\b|-)', text)
    if not start_here_exception:
        for start, end, block in html_blocks(text):
            if re.search(r"<style\b", block, re.I):
                style_offset = start + re.search(r"<style\b", block, re.I).start()
                line = line_of(text, style_offset)
                has_viz = bool(re.search(r'class=["\'][^"\']*\bhpb-viz(?:\b|--)', block))
                has_legacy = bool(re.search(r'class=["\'][^"\']*\bhpb-(?:art|clv)-', block))
                sev = "WARN" if has_legacy else ("ERROR" if has_viz else "WARN")
                add_finding(findings, Finding("HPB-WP-003", sev, line,
                    "local <style> block in content" + (" containing hpb-viz" if has_viz else ""), source=source), text, config)

    # HPB-WP-004 duplicate IDs.
    ids: dict[str, list[int]] = defaultdict(list)
    for el in root.xpath("//*[@id]"):
        ids[el.get("id")].append(el_line(el))
    for ident, lines in ids.items():
        if len(lines) > 1:
            for line in lines[1:]:
                add_finding(findings, Finding("HPB-WP-004", "ERROR", line,
                    f'duplicate id="{ident}" (first occurrence line {lines[0]})', source=source), text, config)

    # HPB-WP-005 tables.
    # Local page CSS can satisfy the same mechanical contract as inline CSS.
    # We only credit class-based declarations that are actually present in this
    # page's own <style> blocks; this does not guess about external/theme CSS.
    local_style_text = "\n".join((el.text or "") for el in root.xpath("//style"))
    local_style_rules = []
    if local_style_text.strip():
        try:
            local_nodes = tinycss2.parse_stylesheet(local_style_text, skip_comments=True, skip_whitespace=True)
            local_style_rules = list(flatten_css_rules(local_nodes))
        except Exception:
            local_style_rules = []

    def local_class_declares(class_name: str, prop: str, value_re: Optional[re.Pattern] = None) -> bool:
        for rule, _media in local_style_rules:
            decls = declaration_entries(rule)
            if not any(p == prop and (value_re is None or value_re.search(v.replace(" ", ""))) for p, v, _imp, _ln in decls):
                continue
            for selector in split_selectors(rule.prelude):
                if class_name in class_tokens(selector):
                    return True
        return False

    for table in root.xpath("//table"):
        line = el_line(table)
        table_classes = set((table.get("class") or "").split())
        style = (table.get("style") or "").lower().replace(" ", "")
        has_min = "min-width:" in style
        has_wrapper = False
        has_calc_wrapper = False
        ancestor_classes: set[str] = set()
        parent = table.getparent()
        depth = 0
        while parent is not None and depth < 3:
            pstyle = (parent.get("style") or "").lower().replace(" ", "")
            parent_classes = set((parent.get("class") or "").split())
            ancestor_classes.update(parent_classes)
            if "hpb-calc-tablewrap" in parent_classes:
                has_calc_wrapper = True
            if re.search(r"overflow-x:(auto|scroll)(?:;|$)", pstyle):
                has_wrapper = True
            parent = parent.getparent()
            depth += 1

        # Controlled calculator exception: the global HPB calculator CSS contract
        # gives .hpb-calc-tablewrap overflow-x:auto and .hpb-calc-table a min-width.
        calc_css_contract = "hpb-calc-table" in table_classes and has_calc_wrapper
        if calc_css_contract:
            has_wrapper = True
            has_min = True

        # Local class-based CSS contract. Example: .hpb-pm-table-wrap supplies
        # overflow-x:auto while .hpb-pm-table supplies min-width.
        if not has_min:
            has_min = any(local_class_declares(cls, "min-width") for cls in table_classes)
        if not has_wrapper:
            overflow_re = re.compile(r"^(?:auto|scroll)$", re.I)
            has_wrapper = any(local_class_declares(cls, "overflow-x", overflow_re) for cls in ancestor_classes)

        missing = []
        if not has_wrapper:
            missing.append("scroll wrapper with overflow-x:auto/scroll within 3 ancestors")
        if not has_min:
            missing.append("table min-width")
        if missing:
            # Three known pre-A3 article tables have an explicit mobile fallback
            # (stacked table or separate cards). They still violate the current
            # wrapper+min-width invariant, so keep them visible as legacy WARNs
            # rather than pretending they are canonical PASSes.
            legacy_mobile_table = False
            if target_url == "https://howprosbet.com/bankroll-management-for-sharp-betting/" and "hpb-friction-table" in table_classes:
                legacy_mobile_table = True
            elif target_url == "https://howprosbet.com/essential-tools-for-serious-bettors/":
                legacy_mobile_table = any("hpb-art-tools" in cls for cls in ancestor_classes)
            elif target_url == "https://howprosbet.com/how-bookmaker-odds-are-made/":
                legacy_mobile_table = any("hpb-devig-table" in cls for cls in ancestor_classes)

            sev = "WARN" if legacy_mobile_table else "ERROR"
            msg = "table missing " + " and ".join(missing)
            if legacy_mobile_table:
                msg += "; known legacy mobile fallback exists, migrate when article is next touched"
            add_finding(findings, Finding("HPB-WP-005", sev, line, msg, source=source), text, config)

    # HPB-WP-007 inline event handlers.
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for attr in el.attrib:
            if re.match(r"^on[a-z]+$", attr, re.I):
                add_finding(findings, Finding("HPB-WP-007", "ERROR", el_line(el),
                    f"inline event handler {attr}= found", source=source), text, config)

    # HPB-WP-008 auto-fit/auto-fill grids with 4/5 direct children.
    for el in root.xpath('//*[@style]'):
        style = el.get("style") or ""
        if re.search(r"repeat\(\s*auto-(?:fit|fill)\s*,", style, re.I):
            children = [c for c in el if isinstance(c.tag, str)]
            if len(children) in (4, 5):
                mm = re.search(r"minmax\(\s*([^,\)]+)", style, re.I)
                detail = f"; minmax minimum={mm.group(1).strip()}" if mm else ""
                add_finding(findings, Finding("HPB-WP-008", "WARN", el_line(el),
                    f"auto-fit/auto-fill grid has {len(children)} direct elements{detail}", source=source), text, config)

    # HPB-LINK-* and TXT rules requiring hrefs.
    hrefs: list[tuple[str, int, Any]] = []
    for a in root.xpath("//a[@href]"):
        hrefs.append((a.get("href") or "", el_line(a), a))

    excluded_domains = [d.lower() for d in config.get("excluded_source_domains", [])]
    excluded_host_tokens = [d.lower() for d in config.get("excluded_host_tokens", [])]
    excluded_href_patterns = [re.compile(x, re.I) for x in config.get("excluded_href_patterns", [])]
    money_urls = {u for u, meta in roles.items() if str(meta.get("role", "")).lower() == "money"}
    internal_targets: set[str] = set()

    for href, line, a in hrefs:
        h = href.strip()
        if h.startswith("/") and not h.startswith("//") and not h.startswith("/#"):
            add_finding(findings, Finding("HPB-LINK-001", "ERROR", line,
                f"relative internal link: {h}", source=source), text, config)

        m = re.match(r"^https?://(www\.)?howprosbet\.com(?P<rest>/.*|$)", h, re.I)
        if m and not h.startswith(origin):
            add_finding(findings, Finding("HPB-LINK-002", "ERROR", line,
                f"internal link uses non-canonical scheme/host: {h}", source=source), text, config)

        p = urlparse(h)
        if p.scheme.lower() == "https" and (p.hostname or "").lower() == config["site_host"]:
            path = p.path or "/"
            internal_targets.add(urlunparse(("https", config["site_host"], path, "", p.query, "")))
            if not p.fragment and not p.query and path != "/" and not path.endswith("/") and not FILE_EXT_RE.search(path):
                add_finding(findings, Finding("HPB-LINK-003", "WARN", line,
                    f"internal page link lacks trailing slash: {h}", source=source), text, config)

        host = (p.hostname or "").lower()
        if host and (
            any(host == d or host.endswith("." + d) for d in excluded_domains)
            or any(tok in host for tok in excluded_host_tokens)
            or any(pat.search(h) for pat in excluded_href_patterns)
        ):
            add_finding(findings, Finding("HPB-LINK-004", "ERROR", line,
                f"excluded source linked: {h}", source=source), text, config)

        target = normalize_internal_href(h, origin)
        if target:
            # Role checks care where the link points, even when LINK-001 separately
            # reports that the source used a forbidden relative href. This avoids
            # cascading "missing hub/money link" warnings for a link that exists.
            internal_targets.add(target)
        if target and inventory is not None and target not in inventory:
            add_finding(findings, Finding("HPB-LINK-005", "ERROR", line,
                f"internal link target is absent from 200-URL inventory: {target}", source=source), text, config)

        if "researchgate.net" in h.lower():
            add_finding(findings, Finding("HPB-TXT-008", "WARN", line,
                "ResearchGate used as citation source", source=source), text, config)

    if inventory is None:
        findings.append(Finding("HPB-LINK-005", "INFO", 1,
            "URL inventory not supplied; unknown-target check skipped", source=source))

    # HPB-LINK-006/007 role aware.
    if target_url:
        meta = roles.get(target_url)
        if meta:
            role = str(meta.get("role", "")).lower()
            silo = meta.get("silo")
            if role not in {"hub", "furniture"}:
                expected_hub = config.get("silo_hub_by_name", {}).get(silo)
                ok = expected_hub in internal_targets if expected_hub else bool(set(config.get("hub_urls", [])) & internal_targets)
                if not ok:
                    add_finding(findings, Finding("HPB-LINK-006", "WARN", 1,
                        f"missing silo-hub backlink{f' to {expected_hub}' if expected_hub else ''}", source=source), text, config)
            if role == "bridge" and not (money_urls & internal_targets):
                add_finding(findings, Finding("HPB-LINK-007", "WARN", 1,
                    "Bridge page has no link to a mapped Money page", source=source), text, config)
        else:
            findings.append(Finding("HPB-META-001", "INFO", 1,
                f"no roadmap role mapping for {target_url}; role-dependent checks skipped", source=source))
    else:
        findings.append(Finding("HPB-META-001", "INFO", 1,
            "target URL not supplied; URL-bound and role-dependent checks skipped", source=source))

    # HPB-A11Y-001 img alt.
    for img in root.xpath("//img"):
        if "alt" not in img.attrib:
            add_finding(findings, Finding("HPB-A11Y-001", "ERROR", el_line(img),
                "<img> missing alt attribute", source=source), text, config)

    # HPB-A11Y-002 regions/navigation.
    for el in root.xpath('//*[@role="region" or @role="navigation"]'):
        if not el.get("aria-label") and not el.get("aria-labelledby"):
            add_finding(findings, Finding("HPB-A11Y-002", "WARN", el_line(el),
                f'role="{el.get("role")}" lacks aria-label/aria-labelledby', source=source), text, config)

    # HPB-A11Y-003 heading jumps and A11Y-004 h1.
    headings = []
    for el in root.xpath("//h1|//h2|//h3|//h4|//h5|//h6"):
        level = int(el.tag[1])
        headings.append((level, el_line(el)))
        if level == 1:
            add_finding(findings, Finding("HPB-A11Y-004", "WARN", el_line(el),
                "<h1> found inside supplied content", source=source), text, config)
    for (prev, _), (cur, line) in zip(headings, headings[1:]):
        if cur - prev > 1:
            add_finding(findings, Finding("HPB-A11Y-003", "WARN", line,
                f"heading hierarchy jumps from h{prev} to h{cur}", source=source), text, config)

    # SVG rules. lxml HTML parser lowercases viewBox to viewbox.
    for svg in root.xpath("//*[local-name()='svg']"):
        line = el_line(svg)
        attrs_lower = {k.lower(): v for k, v in svg.attrib.items()}
        if "viewbox" not in attrs_lower:
            add_finding(findings, Finding("HPB-SVG-001", "WARN", line,
                "inline SVG missing viewBox", source=source), text, config)
        decorative = attrs_lower.get("aria-hidden", "").lower() == "true"
        titled = any((getattr(c, "tag", "").split("}")[-1].lower() == "title") for c in svg.iterdescendants())
        labelled = attrs_lower.get("role", "").lower() == "img" and ("aria-label" in attrs_lower or titled)
        if not (decorative or labelled):
            add_finding(findings, Finding("HPB-SVG-002", "WARN", line,
                "inline SVG is neither aria-hidden nor role=img with accessible label/title", source=source), text, config)
        texts = [c for c in svg.iterdescendants() if isinstance(getattr(c, "tag", None), str) and c.tag.split("}")[-1].lower() == "text"]
        if len(texts) >= 6:
            add_finding(findings, Finding("HPB-SVG-003", "INFO", line,
                f"inline SVG contains {len(texts)} <text> elements", source=source), text, config)

    # HPB-CSS-004 on content class token.
    # .hpb-next is legacy-but-valid only inside the bookmakers/tools hub scopes.
    hub_next_exception = False
    if target_url == "https://howprosbet.com/bookmakers/":
        hub_next_exception = bool(root.xpath(
            '//*[contains(concat(" ", normalize-space(@class), " "), " hpb-hub--bookmakers ")]'
        ))
    elif target_url == "https://howprosbet.com/tools-bankroll/":
        hub_next_exception = bool(root.xpath(
            '//*[contains(concat(" ", normalize-space(@class), " "), " hpb-hub--tools ")]'
        ))
    if not hub_next_exception:
        for el in root.xpath('//*[contains(concat(" ", normalize-space(@class), " "), " hpb-next ")]'):
            add_finding(findings, Finding("HPB-CSS-004", "ERROR", el_line(el),
                ".hpb-next used outside the allowed bookmakers/tools hub scope", source=source), text, config)

    # Text scope.
    # Reparse so dropping script/style did not mutate other checks.
    text_root = lxml_document(text)
    visible = extract_text(text_root)
    visible_lower = visible.lower()

    if "—" in visible:
        # One finding per page, but report the total count so a cleanup pass
        # does not discover additional em-dashes one run at a time.
        em_count = visible.count("—")
        masked = re.sub(
            r"<!--.*?-->",
            lambda m: "".join("\n" if ch == "\n" else " " for ch in m.group(0)),
            text,
            flags=re.S,
        )
        pos = masked.find("—")
        add_finding(findings, Finding("HPB-TXT-001", "ERROR", line_of(text, pos if pos >= 0 else 0),
            f"em-dash U+2014 found in visible text ({em_count} occurrence{'s' if em_count != 1 else ''} on page)", source=source), text, config)

    for name in config.get("excluded_source_names", []):
        pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(name) + r"(?![A-Za-z0-9])", re.I)
        if pat.search(visible):
            raw = pat.search(text)
            add_finding(findings, Finding("HPB-TXT-002", "ERROR", line_of(text, raw.start() if raw else 0),
                f"excluded source named in text: {name}", source=source), text, config)

    for dom in config.get("excluded_source_domains", []):
        pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(dom) + r"(?![A-Za-z0-9])", re.I)
        if pat.search(visible):
            raw = pat.search(text)
            add_finding(findings, Finding("HPB-TXT-002", "ERROR", line_of(text, raw.start() if raw else 0),
                f"excluded source domain named in text: {dom}", source=source), text, config)

    if re.search(r"397[,.]935", visible):
        pos = re.search(r"397[,.]935", text)
        add_finding(findings, Finding("HPB-TXT-003", "ERROR", line_of(text, pos.start() if pos else 0),
            "forbidden 397,935 fingerprint found", source=source), text, config)
    for m in re.finditer(r"0[,.]997", visible, re.I):
        lo, hi = max(0, m.start() - 80), min(len(visible), m.end() + 80)
        if re.search(r"R²|\bR2\b", visible[lo:hi], re.I):
            pos = re.search(r"0[,.]997", text, re.I)
            add_finding(findings, Finding("HPB-TXT-003", "ERROR", line_of(text, pos.start() if pos else 0),
                "forbidden R²/R2 0.997 fingerprint found", source=source), text, config)
            break

    pct_matches = list(re.finditer(r"(?:3\s*(?:-|–|to)\s*5\s*(?:%|percent)|3\s*%\s*(?:-|–|to)\s*5\s*%)", visible, re.I))
    for m in pct_matches:
        lo, hi = max(0, m.start() - 120), min(len(visible), m.end() + 120)
        if re.search(r"profitable|winning|bettors", visible[lo:hi], re.I):
            add_finding(findings, Finding("HPB-TXT-004", "WARN", 1,
                "possible '3 to 5 percent of bettors are profitable' claim", source=source), text, config)
            break

    for sm in re.finditer(r"\bSportmarket\b", visible, re.I):
        lo, hi = max(0, sm.start() - 300), min(len(visible), sm.end() + 300)
        if CURACAO_RE.search(visible[lo:hi]):
            # Use a real lexical Curaçao/Curacao match. The former r"Cura"
            # also matched words such as "accurate" and caused false positives.
            raw_cur = CURACAO_RE.search(text)
            raw_sm = re.search(r"\bSportmarket\b", text, re.I)
            raw_pos = raw_cur.start() if raw_cur else (raw_sm.start() if raw_sm else 0)
            add_finding(findings, Finding("HPB-TXT-005", "WARN", line_of(text, raw_pos),
                "Sportmarket and Curaçao/Curacao appear within 300 characters", source=source), text, config)
            break

    if re.search(r"Levitt", visible, re.I) and re.search(r"Journal of Political Economy", visible, re.I):
        add_finding(findings, Finding("HPB-TXT-006", "ERROR", 1,
            "Levitt is paired with Journal of Political Economy", source=source), text, config)

    for cm in CURACAO_RE.finditer(visible):
        lo, hi = max(0, cm.start() - 300), min(len(visible), cm.end() + 300)
        if re.search(r"\bGCB\b", visible[lo:hi], re.I):
            raw_cur = CURACAO_RE.search(text)
            raw_pos = raw_cur.start() if raw_cur else 0
            add_finding(findings, Finding("HPB-TXT-007", "WARN", line_of(text, raw_pos),
                "GCB appears near Curaçao/Curacao; current regulator is CGA", source=source), text, config)
            break

    if re.search(r"Buchdahl", visible, re.I):
        if not any("football-data.co.uk" in h.lower() for h, _, _ in hrefs):
            add_finding(findings, Finding("HPB-TXT-009", "WARN", 1,
                "Buchdahl mentioned without a football-data.co.uk link", source=source), text, config)

    return sorted(findings, key=lambda f: f.key())


def split_selectors(prelude_tokens) -> list[str]:
    groups = []
    cur = []
    for tok in prelude_tokens:
        if getattr(tok, "type", None) == "literal" and getattr(tok, "value", None) == ",":
            s = tinycss2.serialize(cur).strip()
            if s:
                groups.append(s)
            cur = []
        else:
            cur.append(tok)
    s = tinycss2.serialize(cur).strip()
    if s:
        groups.append(s)
    return groups


def normalize_selector(s: str) -> str:
    s = re.sub(r"\s+", " ", s.strip())
    s = re.sub(r"\s*([>+~])\s*", r"\1", s)
    return s.lower()


def class_tokens(selector: str) -> list[str]:
    return CLASS_RE.findall(selector)


def hpb_systems(tokens: Iterable[str]) -> set[str]:
    systems = set()
    for t in tokens:
        if t.startswith("hpb-footer"):
            systems.add("chrome")
        elif t.startswith("hpb-home"):
            systems.add("home")
        elif t.startswith("hpb-hub"):
            systems.add("hub")
        elif t == "hpb-page" or t.startswith("hpb-page-"):
            systems.add("page")
        elif t == "hpb-sh" or t.startswith("hpb-sh-"):
            systems.add("sh")
        elif t == "hpb-calc" or t.startswith("hpb-calc-"):
            systems.add("calc")
        elif t == "hpb-viz" or t.startswith("hpb-viz"):
            systems.add("viz")
        elif t.startswith("hpb-art") or t.startswith("hpb-clv"):
            systems.add("art")
    return systems


def allowed_first_hpb(token: str) -> bool:
    return (
        token.startswith("hpb-footer-") or token == "hpb-page" or token.startswith("hpb-page-") or
        token == "hpb-calc" or token.startswith("hpb-calc-") or token == "hpb-viz" or
        token.startswith("hpb-viz--") or (token.startswith("hpb-viz-") and "__" in token) or
        token == "hpb-home" or token == "hpb-hub" or token.startswith("hpb-art") or token.startswith("hpb-clv")
    )


def flatten_css_rules(nodes, media: str = ""):
    for node in nodes:
        if node.type == "qualified-rule":
            yield node, media
        elif node.type == "at-rule" and node.content is not None:
            name = node.lower_at_keyword
            ctx = media
            if name == "media":
                cond = tinycss2.serialize(node.prelude).strip()
                ctx = f"{media} @media {cond}".strip()
            nested = tinycss2.parse_rule_list(node.content, skip_comments=True, skip_whitespace=True)
            yield from flatten_css_rules(nested, ctx)


def declaration_entries(rule) -> list[tuple[str, str, bool, int]]:
    out = []
    for d in tinycss2.parse_declaration_list(rule.content, skip_comments=True, skip_whitespace=True):
        if d.type == "declaration":
            out.append((d.lower_name, tinycss2.serialize(d.value).strip(), bool(d.important), getattr(d, "source_line", rule.source_line)))
    return out


def lint_css(text: str, source: str, config: dict, baseline_text: Optional[str] = None) -> list[Finding]:
    findings: list[Finding] = []
    nodes = tinycss2.parse_stylesheet(text, skip_comments=True, skip_whitespace=True)
    rules = list(flatten_css_rules(nodes))

    baseline_decl_keys: set[tuple] = set()
    baseline_selectors: set[str] = set()
    if baseline_text is not None:
        bnodes = tinycss2.parse_stylesheet(baseline_text, skip_comments=True, skip_whitespace=True)
        for brule, bmedia in flatten_css_rules(bnodes):
            for bsel in split_selectors(brule.prelude):
                nsel = normalize_selector(bsel)
                baseline_selectors.add((bmedia.lower(), nsel))
                for prop, val, imp, _ in declaration_entries(brule):
                    baseline_decl_keys.add((bmedia.lower(), nsel, prop, re.sub(r"\s+", "", val.lower()), imp))

    dup_map: dict[tuple[str, str, str], list[tuple[str, int]]] = defaultdict(list)
    legacy_exact = set(config.get("legacy_exact_tokens", []))
    legacy_fams = [re.compile(x) for x in config.get("legacy_family_patterns", [])]
    deny_hex = set(x.lower() for x in config.get("semantic_color_denylist", []))
    deny_rgba = [x.lower().replace(" ", "") for x in config.get("semantic_color_rgba_prefixes", [])]
    color_context = set(config.get("semantic_color_allowed_context_tokens", []))
    autofit_exception = normalize_selector(config.get("css_autofit_exception", ""))

    for rule, media in rules:
        decls = declaration_entries(rule)
        for selector in split_selectors(rule.prelude):
            nsel = normalize_selector(selector)
            tokens = class_tokens(selector)
            hpb_tokens = [t for t in tokens if t.startswith("hpb-")]
            line = getattr(rule, "source_line", 1)

            # HPB-CSS-001
            bad = [t for t in tokens if t in legacy_exact or any(p.match(t) for p in legacy_fams)]
            for t in sorted(set(bad)):
                add_finding(findings, Finding("HPB-CSS-001", "ERROR", line,
                    f"forbidden legacy global class .{t} in selector {selector}", source=source), text, config)

            # HPB-CSS-002
            if re.match(r"^body\s+\.hpb-(hub|home)$", nsel):
                add_finding(findings, Finding("HPB-CSS-002", "ERROR", line,
                    f"forbidden global scope override: {selector}", source=source), text, config)

            # HPB-CSS-003
            if "hpb-hub" in tokens and not any(t.startswith("hpb-hub--") for t in tokens):
                add_finding(findings, Finding("HPB-CSS-003", "ERROR", line,
                    f"hub selector lacks hub modifier: {selector}", source=source), text, config)

            # HPB-CSS-004
            if "hpb-next" in tokens and not ({"hpb-hub--bookmakers", "hpb-hub--tools"} & set(tokens)):
                add_finding(findings, Finding("HPB-CSS-004", "ERROR", line,
                    f".hpb-next outside bookmakers/tools hub scope: {selector}", source=source), text, config)

            # HPB-CSS-012 first so it can be more precise than CSS-005.
            has_sh = any(t == "hpb-sh" or t.startswith("hpb-sh-") for t in tokens)
            if has_sh:
                add_finding(findings, Finding("HPB-CSS-012", "ERROR", line,
                    f"Start Here namespace found in Additional CSS: {selector}", source=source), text, config)

            # HPB-CSS-005
            if hpb_tokens:
                first = hpb_tokens[0]
                if not allowed_first_hpb(first) and not has_sh:
                    add_finding(findings, Finding("HPB-CSS-005", "ERROR", line,
                        f"unscoped/unknown first HPB token .{first}: {selector}", source=source), text, config)

            # HPB-CSS-006
            systems = hpb_systems(tokens)
            if len(systems) > 1:
                add_finding(findings, Finding("HPB-CSS-006", "ERROR", line,
                    f"cross-scope selector mixes {', '.join(sorted(systems))}: {selector}", source=source), text, config)

            # HPB-CSS-007
            if nsel.startswith("body") and hpb_tokens:
                only_compat = all(t.startswith("hpb-art") or t.startswith("hpb-clv") for t in hpb_tokens)
                if not only_compat:
                    add_finding(findings, Finding("HPB-CSS-007", "ERROR", line,
                        f"body-prefixed HPB selector outside compatibility layer: {selector}", source=source), text, config)
                elif baseline_text is not None and (media.lower(), nsel) not in baseline_selectors:
                    add_finding(findings, Finding("HPB-CSS-007", "ERROR", line,
                        f"new body-prefixed compatibility selector in diff: {selector}", source=source), text, config)

            # Per-declaration CSS rules.
            for prop, val, important, dline in decls:
                compact = re.sub(r"\s+", "", val.lower())
                dup_map[(media.lower(), nsel, prop)].append((compact + ("!important" if important else ""), dline))

                # HPB-CSS-008
                contains_bad_color = any(c in compact for c in deny_hex) or any(c in compact for c in deny_rgba)
                if contains_bad_color and not (set(tokens) & color_context):
                    add_finding(findings, Finding("HPB-CSS-008", "ERROR", dline,
                        f"semantic red/orange color used outside allowed state context in {selector}: {prop}:{val}", source=source), text, config)

                # HPB-CSS-009 only diff.
                if important and baseline_text is not None:
                    decl_key = (media.lower(), nsel, prop, compact, True)
                    if decl_key not in baseline_decl_keys:
                        systems_here = hpb_systems(tokens)
                        if systems_here & {"home", "hub", "viz"}:
                            add_finding(findings, Finding("HPB-CSS-009", "WARN", dline,
                                f"new !important in {','.join(sorted(systems_here))} scope: {selector} {prop}", source=source), text, config)

                # HPB-CSS-011
                if re.search(r"repeat\(\s*auto-(?:fit|fill)\s*,", val, re.I) and nsel != autofit_exception:
                    add_finding(findings, Finding("HPB-CSS-011", "WARN", dline,
                        f"auto-fit/auto-fill grid in global CSS: {selector}", source=source), text, config)

    # HPB-CSS-010 contradictory duplicates within same media context.
    for (media, selector, prop), vals in dup_map.items():
        unique = {v for v, _ in vals}
        if len(unique) > 1:
            line = vals[-1][1]
            add_finding(findings, Finding("HPB-CSS-010", "INFO", line,
                f"selector {selector} sets {prop} to different values in same media context: {sorted(unique)}", source=source), text, config)

    if baseline_text is None:
        findings.append(Finding("HPB-CSS-009", "INFO", 1,
            "diff baseline not supplied; new-!important rule skipped", source=source))

    return sorted(findings, key=lambda f: f.key())


def crawl_coverage(inventory_path: str, roles_path: Optional[str], inlinks_path: Optional[str] = None) -> dict[str, Any]:
    roles = load_roles(roles_path)
    rows = []
    with open(inventory_path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    indexable = []
    for row in rows:
        addr = row.get("Adresse") or row.get("Address")
        status = str(row.get("Status-Code") or row.get("Status Code") or "")
        idx = str(row.get("Indexierbarkeit") or row.get("Indexability") or "")
        if status == "200" and idx.lower() in {"indexierbar", "indexable"}:
            indexable.append(addr)
    missing_roles = sorted([u for u in indexable if u not in roles])
    stale_roles = sorted([u for u in roles if u not in indexable])
    broken_internal = []
    if inlinks_path:
        with open(inlinks_path, encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                dest = row.get("Nach") or row.get("To")
                src = row.get("Von") or row.get("From")
                code = str(row.get("Status-Code") or row.get("Status Code") or "")
                if dest and dest.startswith("https://howprosbet.com/") and code and code != "200":
                    broken_internal.append({"from": src, "to": dest, "status": code})
    return {
        "inventory_rows": len(rows),
        "indexable_200_urls": len(indexable),
        "role_mappings": len(roles),
        "missing_role_mappings": missing_roles,
        "stale_role_mappings": stale_roles,
        "non_200_internal_inlinks": broken_internal[:100],
        "non_200_internal_inlinks_count": len(broken_internal),
    }




def canonical_page_url(url: str, config: dict) -> Optional[str]:
    """Normalize a WXR page URL to the site's canonical page form."""
    if not url:
        return None
    origin = config["site_origin"]
    host = config["site_host"]
    p = urlparse(url.strip())
    if (p.hostname or "").lower() not in {host, "www." + host}:
        return None
    path = p.path or "/"
    if path != "/" and not path.endswith("/") and not FILE_EXT_RE.search(path):
        path += "/"
    return urlunparse(("https", host, path, "", "", ""))


def parse_indexable_inventory(path: Optional[str]) -> set[str]:
    """Return indexable HTTP-200 URLs from a Screaming Frog intern_html export."""
    if not path:
        return set()
    urls: set[str] = set()
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            addr = (row.get("Adresse") or row.get("Address") or "").strip()
            status = str(row.get("Status-Code") or row.get("Status Code") or "").strip()
            idx = str(row.get("Indexierbarkeit") or row.get("Indexability") or "").strip().lower()
            if addr and status == "200" and idx in {"indexierbar", "indexable"}:
                urls.add(addr)
    return urls


def wxr_child_text(item: ET.Element, local_name: str, namespace_hint: Optional[str] = None) -> str:
    """Read a WXR child by local name, optionally preferring a namespace fragment."""
    candidates = []
    for child in list(item):
        tag = child.tag
        if not isinstance(tag, str):
            continue
        local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
        if local == local_name:
            candidates.append(child)
    if namespace_hint:
        for child in candidates:
            if namespace_hint in child.tag:
                return child.text or ""
    return (candidates[0].text or "") if candidates else ""


def parse_wxr_items(path: str, config: dict) -> list[dict[str, str]]:
    """Extract published post/page content from a WordPress WXR export."""
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        raise ValueError(f"invalid WordPress XML/WXR: {e}") from e
    root = tree.getroot()
    items: list[dict[str, str]] = []
    for item in root.iter():
        tag = item.tag
        if not isinstance(tag, str):
            continue
        local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
        if local != "item":
            continue
        post_type = wxr_child_text(item, "post_type", "wordpress.org/export").strip().lower()
        status = wxr_child_text(item, "status", "wordpress.org/export").strip().lower()
        if post_type not in {"post", "page"} or status != "publish":
            continue
        link = wxr_child_text(item, "link").strip()
        target_url = canonical_page_url(link, config)
        title = wxr_child_text(item, "title").strip()
        content = wxr_child_text(item, "encoded", "purl.org/rss/1.0/modules/content")
        # Fallback: some exporters preserve the namespace with a different URI.
        if not content:
            content = wxr_child_text(item, "encoded")
        items.append({
            "url": target_url or "",
            "link": link,
            "title": title,
            "post_type": post_type,
            "content": content or "",
        })
    return items


def lint_wxr(xml_path: str, config: dict, inventory_path: Optional[str], roles_path: Optional[str],
             extract_dir: Optional[str] = None) -> tuple[list[Finding], dict[str, Any]]:
    """Run the HTML linter across published post/page items from a WXR export."""
    items = parse_wxr_items(xml_path, config)
    inventory_200 = parse_inventory(inventory_path)
    indexable = parse_indexable_inventory(inventory_path)
    roles = load_roles(roles_path)

    by_url: dict[str, dict[str, str]] = {}
    duplicate_urls: list[str] = []
    no_url: list[str] = []
    for item in items:
        url = item["url"]
        if not url:
            no_url.append(item["title"] or item["link"] or "(untitled)")
            continue
        if url in by_url:
            duplicate_urls.append(url)
            continue
        by_url[url] = item

    if indexable:
        target_urls = sorted(indexable & set(by_url))
        missing_from_wxr = sorted(indexable - set(by_url))
        published_not_indexable = sorted(set(by_url) - indexable)
    else:
        target_urls = sorted(by_url)
        missing_from_wxr = []
        published_not_indexable = []

    if extract_dir:
        out = Path(extract_dir)
        out.mkdir(parents=True, exist_ok=True)
        for url in target_urls:
            item = by_url[url]
            slug = urlparse(url).path.strip("/") or "home"
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", slug).strip("-") or "home"
            (out / f"{safe}.txt").write_text(item["content"], encoding="utf-8")

    all_findings: list[Finding] = []
    per_page: list[dict[str, Any]] = []
    for url in target_urls:
        item = by_url[url]
        page_findings = lint_html(item["content"], url, url, config, inventory_200, roles)
        counts = {sev: sum(1 for f in page_findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")}
        per_page.append({
            "url": url,
            "title": item["title"],
            "post_type": item["post_type"],
            **counts,
        })
        all_findings.extend(page_findings)

    extra_findings: list[Finding] = []
    for url in missing_from_wxr:
        extra_findings.append(Finding("HPB-WXR-001", "WARN", 1,
            "indexable crawl URL is missing from published post/page items in WXR export", source=url))
    for title in no_url:
        extra_findings.append(Finding("HPB-WXR-002", "INFO", 1,
            f"published post/page item has no canonical howprosbet.com <link>: {title}", source=xml_path))
    for url in sorted(set(duplicate_urls)):
        extra_findings.append(Finding("HPB-WXR-003", "WARN", 1,
            "duplicate published WXR items resolve to the same canonical URL", source=url))
    all_findings.extend(extra_findings)

    report = {
        "wxr_published_post_pages": len(items),
        "wxr_unique_canonical_urls": len(by_url),
        "indexable_inventory_urls": len(indexable),
        "linted_urls": len(target_urls),
        "missing_from_wxr": missing_from_wxr,
        "published_not_indexable": published_not_indexable,
        "duplicate_urls": sorted(set(duplicate_urls)),
        "published_items_without_canonical_url": no_url,
        "per_page": per_page,
    }
    return sorted(all_findings, key=lambda f: (f.source, *f.key())), report

def autofix_html_links(text: str, config: dict) -> tuple[str, int]:
    """Explicit-only autofix for HPB-LINK-001/002/003, preserving source formatting."""
    origin = config["site_origin"]
    host = config["site_host"]
    count = 0
    attr_re = re.compile(r"(href\s*=\s*)([\"'])(.*?)(\2)", re.I | re.S)

    def repl(m):
        nonlocal count
        prefix, quote, href, closing = m.groups()
        h = href.strip()
        new = href
        if h.startswith("/") and not h.startswith("//"):
            new = origin + h
        else:
            p = urlparse(h)
            if (p.hostname or "").lower() in {host, "www." + host} and p.scheme.lower() in {"http", "https"}:
                new = urlunparse(("https", host, p.path or "/", "", p.query, p.fragment))
        p2 = urlparse(new)
        if p2.scheme == "https" and (p2.hostname or "").lower() == host:
            path = p2.path or "/"
            if not p2.fragment and not p2.query and path != "/" and not path.endswith("/") and not FILE_EXT_RE.search(path):
                new = urlunparse((p2.scheme, p2.netloc, path + "/", "", p2.query, p2.fragment))
        if new != href:
            count += 1
        return prefix + quote + new + closing

    return attr_re.sub(repl, text), count


def write_wxr_link_fix_batch(xml_path: str, config: dict, inventory_path: Optional[str], output_dir: str) -> dict[str, Any]:
    """Write changed published page/post contents with only safe internal href normalization."""
    items = parse_wxr_items(xml_path, config)
    indexable = parse_indexable_inventory(inventory_path)
    by_url = {item["url"]: item for item in items if item.get("url")}
    target_urls = sorted((indexable & set(by_url)) if indexable else set(by_url))
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    changed = []
    total = 0
    for url in target_urls:
        item = by_url[url]
        fixed, count = autofix_html_links(item["content"], config)
        if not count:
            continue
        slug = urlparse(url).path.strip("/") or "home"
        safe = re.sub(r"[^A-Za-z0-9._-]+", "-", slug).strip("-") or "home"
        filename = f"{safe}.txt"
        (out / filename).write_text(fixed, encoding="utf-8")
        changed.append({"url": url, "file": filename, "href_changes": count})
        total += count
    manifest = {
        "source_wxr": str(xml_path),
        "pages_changed": len(changed),
        "href_changes": total,
        "changes": changed,
        "note": "Files contain only HPB-LINK-001/002/003 href normalization. No prose, markup, CSS or schema changes are made.",
    }
    (out / "_manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def print_findings(findings: list[Finding]):
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")}
    print(f"HPB Lint v{VERSION}: {counts['ERROR']} ERROR, {counts['WARN']} WARN, {counts['INFO']} INFO")
    for f in findings:
        loc = f"{f.source}:{f.line}" if f.source else f"line {f.line}"
        print(f"{f.severity:5} {f.rule_id:12} {loc}  {f.message}")
        if f.excerpt:
            print(f"      {f.excerpt}")


BASELINE_FINGERPRINT_VERSION = 1


def _finding_value(item: Any, key: str) -> str:
    if isinstance(item, Finding):
        value = getattr(item, key, "")
    elif isinstance(item, dict):
        value = item.get(key, "")
    else:
        value = ""
    return "" if value is None else str(value)


def finding_fingerprint(item: Any) -> tuple[str, str, str, str]:
    """Stable fingerprint for baseline comparison.

    Deliberately ignores line number and excerpt so harmless line shifts do not
    turn known warnings into new warnings. Counter semantics preserve duplicate
    findings such as multiple identical local <style> warnings on one URL.
    """
    severity = _finding_value(item, "severity").upper().strip()
    rule_id = _finding_value(item, "rule_id").strip()
    source = _finding_value(item, "source").strip()
    message = re.sub(r"\s+", " ", _finding_value(item, "message")).strip()
    return severity, rule_id, source, message


def compare_warning_baseline(findings: list[Finding], baseline_payload: dict, baseline_path: str) -> dict:
    baseline_items = baseline_payload.get("findings")
    if not isinstance(baseline_items, list):
        raise ValueError(f"baseline report has no findings list: {baseline_path}")

    baseline_warn = [x for x in baseline_items if _finding_value(x, "severity").upper() == "WARN"]
    current_warn = [f for f in findings if f.severity == "WARN"]

    remaining = Counter(finding_fingerprint(x) for x in baseline_warn)
    known: list[Finding] = []
    new: list[Finding] = []
    for finding in current_warn:
        fp = finding_fingerprint(finding)
        if remaining[fp] > 0:
            known.append(finding)
            remaining[fp] -= 1
        else:
            new.append(finding)

    resolved: list[dict] = []
    unresolved = remaining.copy()
    for item in baseline_warn:
        fp = finding_fingerprint(item)
        if unresolved[fp] > 0:
            resolved.append(item)
            unresolved[fp] -= 1

    return {
        "baseline_path": baseline_path,
        "baseline_tool": baseline_payload.get("tool"),
        "baseline_version": baseline_payload.get("version"),
        "fingerprint_version": BASELINE_FINGERPRINT_VERSION,
        "counts": {
            "baseline_warn": len(baseline_warn),
            "current_warn": len(current_warn),
            "known_warn": len(known),
            "new_warn": len(new),
            "resolved_warn": len(resolved),
        },
        "new_warn_findings": [asdict(f) for f in new],
        "resolved_warn_findings": resolved,
    }


def write_json_report(path: Optional[str], findings: list[Finding], extra: Optional[dict] = None, baseline_diff: Optional[dict] = None):
    if not path:
        return
    payload = {
        "tool": "hpb_lint.py",
        "version": VERSION,
        "counts": {sev: sum(1 for f in findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")},
        "findings": [asdict(f) for f in findings],
    }
    if extra:
        payload["extra"] = extra
    if baseline_diff is not None:
        payload["baseline_diff"] = baseline_diff
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)



AUTO_CONFIG_NAME = "hpb_lint_config.json"
AUTO_ROLES_NAME = "hpb_roles.json"


def _latest_by_mtime(paths: Iterable[Path]) -> Optional[Path]:
    candidates = list(paths)
    if not candidates:
        return None
    return max(candidates, key=lambda p: (p.stat().st_mtime_ns, p.name.lower()))


def wxr_export_timestamp(path: Path) -> Optional[float]:
    """Read the channel pubDate so copied files are ordered by export time, not copy time."""
    try:
        for _event, elem in ET.iterparse(path, events=("end",)):
            tag = elem.tag if isinstance(elem.tag, str) else ""
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            if local == "pubDate" and (elem.text or "").strip():
                try:
                    return parsedate_to_datetime((elem.text or "").strip()).timestamp()
                except (TypeError, ValueError, OverflowError):
                    return None
            elem.clear()
    except (ET.ParseError, OSError):
        return None
    return None


def _latest_wxr(paths: Iterable[Path]) -> Optional[Path]:
    candidates = list(paths)
    if not candidates:
        return None

    def key(path: Path):
        export_ts = wxr_export_timestamp(path)
        return (export_ts if export_ts is not None else path.stat().st_mtime, path.stat().st_mtime_ns, path.name.lower())

    return max(candidates, key=key)


def is_wordpress_wxr(path: Path) -> bool:
    """Return True only for structurally recognizable WordPress WXR XML files."""
    if not path.is_file() or path.suffix.lower() != ".xml":
        return False
    saw_wxr_version = False
    saw_item = False
    saw_wp_post_type = False
    try:
        for _event, elem in ET.iterparse(path, events=("end",)):
            tag = elem.tag if isinstance(elem.tag, str) else ""
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            if local == "wxr_version" and "wordpress.org/export" in tag:
                saw_wxr_version = True
            elif local == "post_type" and "wordpress.org/export" in tag:
                saw_wp_post_type = True
            elif local == "item":
                saw_item = True
            if saw_wxr_version and saw_item and saw_wp_post_type:
                return True
            elem.clear()
    except (ET.ParseError, OSError):
        return False
    return False


def is_inventory_csv(path: Path) -> bool:
    """Recognize a Screaming Frog internal-HTML inventory by its header."""
    if not path.is_file() or path.suffix.lower() != ".csv":
        return False
    try:
        with open(path, encoding="utf-8-sig", newline="") as f:
            fieldnames = set(csv.DictReader(f).fieldnames or [])
    except (OSError, UnicodeError, csv.Error):
        return False
    has_address = bool({"Adresse", "Address"} & fieldnames)
    has_status = bool({"Status-Code", "Status Code"} & fieldnames)
    has_indexability = bool({"Indexierbarkeit", "Indexability"} & fieldnames)
    return has_address and has_status and has_indexability


def is_green_baseline(path: Path) -> bool:
    """Recognize an HPB JSON baseline suitable for WARN fingerprint comparison."""
    if not path.is_file() or path.suffix.lower() != ".json":
        return False
    try:
        data = load_json(str(path), {})
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(data, dict)
        and data.get("tool") == "hpb_lint.py"
        and isinstance(data.get("findings"), list)
        and isinstance(data.get("counts"), dict)
    )


def discover_auto_inputs(directory: Path) -> dict[str, Path]:
    """Find the standard HPB sitewide inputs next to hpb_lint.py.

    The WXR, inventory and Green baseline may be replaced over time, so the
    newest valid matching file is selected. Config and roles use stable names.
    """
    directory = directory.resolve()

    config = directory / AUTO_CONFIG_NAME
    if not config.is_file():
        raise ValueError(f"missing {AUTO_CONFIG_NAME} in {directory}")

    roles = directory / AUTO_ROLES_NAME
    if not roles.is_file():
        raise ValueError(f"missing {AUTO_ROLES_NAME} in {directory}")

    wxr = _latest_wxr(
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() == ".xml" and is_wordpress_wxr(p)
    )
    if wxr is None:
        raise ValueError(f"no valid WordPress WXR .xml file found in {directory}")

    inventory = _latest_by_mtime(
        p for p in directory.iterdir()
        if p.is_file() and "intern_html" in p.name.lower() and is_inventory_csv(p)
    )
    if inventory is None:
        raise ValueError(f"no valid intern_html inventory CSV found in {directory}")

    green_named = [
        p for p in directory.iterdir()
        if p.is_file() and p.suffix.lower() == ".json"
        and p.name.lower().startswith("hpb_baseline_green")
        and is_green_baseline(p)
    ]
    baseline = _latest_by_mtime(green_named)
    if baseline is None:
        raise ValueError(f"no valid hpb_baseline_GREEN*.json found in {directory}")

    return {
        "wxr": wxr,
        "inventory": inventory,
        "roles": roles,
        "config": config,
        "baseline": baseline,
    }


def auto_cli_args(inputs: dict[str, Path]) -> list[str]:
    """Translate zero-argument mode into the existing v0.2.4 WXR CLI."""
    return [
        "wxr", str(inputs["wxr"]),
        "--config", str(inputs["config"]),
        "--inventory", str(inputs["inventory"]),
        "--roles", str(inputs["roles"]),
        "--baseline", str(inputs["baseline"]),
    ]

def main() -> int:
    auto_mode = len(sys.argv) == 1
    auto_inputs: Optional[dict[str, Path]] = None
    cli_args: Optional[list[str]] = None
    if auto_mode:
        try:
            auto_inputs = discover_auto_inputs(Path(__file__).resolve().parent)
            cli_args = auto_cli_args(auto_inputs)
        except (OSError, ValueError) as e:
            print(f"AUTO SETUP ERROR: {e}", file=sys.stderr)
            print("ACTION REQUIRED")
            return 2

    ap = argparse.ArgumentParser(description="HowProsBet deterministic linter")
    ap.add_argument("--version", action="version", version=f"hpb_lint.py {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default="hpb_lint_config.json")
    common.add_argument("--json-out")

    pcss = sub.add_parser("css", parents=[common], help="lint Additional CSS")
    pcss.add_argument("file")
    pcss.add_argument("--baseline-css", help="optional baseline for diff-only rules")

    phtml = sub.add_parser("html", parents=[common], help="lint WordPress article/page HTML")
    phtml.add_argument("file")
    phtml.add_argument("--url", dest="target_url")
    phtml.add_argument("--inventory", help="Screaming Frog intern_html CSV")
    phtml.add_argument("--roles", help="hpb_roles.json exported from roadmap")
    phtml.add_argument("--fix-out", help="explicitly write a copy with only HPB-LINK-001/002/003 autofixes")

    pcrawl = sub.add_parser("crawl", parents=[common], help="audit crawl/role coverage used by the linter")
    pcrawl.add_argument("inventory")
    pcrawl.add_argument("--roles")
    pcrawl.add_argument("--inlinks")

    pwxr = sub.add_parser("wxr", parents=[common], help="lint all published post/page content in a WordPress WXR export")
    pwxr.add_argument("file", help="WordPress .xml export")
    pwxr.add_argument("--inventory", help="Screaming Frog intern_html CSV; limits sitewide run to indexable 200 URLs")
    pwxr.add_argument("--roles", help="hpb_roles.json exported from roadmap")
    pwxr.add_argument("--extract-dir", help="optional directory to write extracted WordPress blockcode per linted URL")
    pwxr.add_argument("--fix-links-dir", help="optional directory to write only pages changed by safe HPB-LINK-001/002/003 autofixes")
    pwxr.add_argument("--baseline", help="optional prior HPB JSON report; suppresses known WARN detail and reports new/resolved WARNs")

    args = ap.parse_args(cli_args)
    config = load_json(args.config, {})

    if auto_mode and auto_inputs is not None:
        print(f"HPB Lint v{VERSION} — AUTO")
        print(f"WXR: {auto_inputs['wxr'].name}")
        print(f"Inventory: {auto_inputs['inventory'].name}")
        print(f"Roles: {auto_inputs['roles'].name}")
        print(f"Baseline: {auto_inputs['baseline'].name}")

    if args.cmd == "css":
        text = Path(args.file).read_text(encoding="utf-8")
        baseline = Path(args.baseline_css).read_text(encoding="utf-8") if args.baseline_css else None
        findings = lint_css(text, args.file, config, baseline)
        print_findings(findings)
        write_json_report(args.json_out, findings)
        return 1 if any(f.severity == "ERROR" for f in findings) else 0

    if args.cmd == "html":
        text = Path(args.file).read_text(encoding="utf-8")
        if args.fix_out:
            text, fixed_count = autofix_html_links(text, config)
            Path(args.fix_out).write_text(text, encoding="utf-8")
            print(f"Autofix wrote {args.fix_out} ({fixed_count} href change(s))")
        inventory = parse_inventory(args.inventory)
        roles = load_roles(args.roles)
        findings = lint_html(text, args.fix_out or args.file, args.target_url, config, inventory, roles)
        print_findings(findings)
        write_json_report(args.json_out, findings)
        return 1 if any(f.severity == "ERROR" for f in findings) else 0

    if args.cmd == "crawl":
        report = crawl_coverage(args.inventory, args.roles, args.inlinks)
        print(f"Inventory rows: {report['inventory_rows']}")
        print(f"Indexable 200 URLs: {report['indexable_200_urls']}")
        print(f"Role mappings: {report['role_mappings']}")
        print(f"Missing role mappings: {len(report['missing_role_mappings'])}")
        for u in report["missing_role_mappings"]:
            print(f"  MISSING ROLE  {u}")
        print(f"Stale role mappings: {len(report['stale_role_mappings'])}")
        for u in report["stale_role_mappings"]:
            print(f"  STALE ROLE    {u}")
        print(f"Non-200 internal inlinks in crawl: {report['non_200_internal_inlinks_count']}")
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        # Coverage gaps are not lint errors. This command is diagnostic.
        return 0

    if args.cmd == "wxr":
        try:
            findings, report = lint_wxr(args.file, config, args.inventory, args.roles, args.extract_dir)
            link_fix_manifest = None
            if args.fix_links_dir:
                link_fix_manifest = write_wxr_link_fix_batch(args.file, config, args.inventory, args.fix_links_dir)
                report["link_fix_batch"] = link_fix_manifest
        except (OSError, ValueError) as e:
            print(f"WXR ERROR: {e}", file=sys.stderr)
            return 2
        baseline_diff = None
        if args.baseline:
            try:
                baseline_payload = load_json(args.baseline, {})
                if not isinstance(baseline_payload, dict):
                    raise ValueError(f"baseline report is not a JSON object: {args.baseline}")
                baseline_diff = compare_warning_baseline(findings, baseline_payload, args.baseline)
            except (OSError, ValueError, json.JSONDecodeError) as e:
                print(f"BASELINE ERROR: {e}", file=sys.stderr)
                return 2

        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")}
        print(f"WXR published posts/pages: {report['wxr_published_post_pages']}")
        print(f"WXR unique canonical URLs: {report['wxr_unique_canonical_urls']}")
        if args.inventory:
            print(f"Indexable inventory URLs: {report['indexable_inventory_urls']}")
            print(f"Linted indexable URLs: {report['linted_urls']}")
            print(f"Indexable URLs missing from WXR: {len(report['missing_from_wxr'])}")
            for u in report['missing_from_wxr']:
                print(f"  MISSING WXR  {u}")
            print(f"Published WXR URLs outside indexable inventory: {len(report['published_not_indexable'])}")
        if args.fix_links_dir and link_fix_manifest is not None:
            print(f"Safe link-fix batch: {link_fix_manifest['href_changes']} href changes across {link_fix_manifest['pages_changed']} URLs -> {args.fix_links_dir}")
        print(f"Sitewide findings: {counts['ERROR']} ERROR, {counts['WARN']} WARN, {counts['INFO']} INFO")

        if baseline_diff is not None:
            bc = baseline_diff["counts"]
            print(f"Baseline WARN diff: {bc['known_warn']} known, {bc['new_warn']} new, {bc['resolved_warn']} resolved")
            print(f"Baseline report: {args.baseline} (HPB Lint v{baseline_diff.get('baseline_version') or 'unknown'})")

            errors = [f for f in findings if f.severity == "ERROR"]
            new_warn_fps = Counter(
                finding_fingerprint(x) for x in baseline_diff["new_warn_findings"]
            )
            new_warns: list[Finding] = []
            for f in findings:
                if f.severity != "WARN":
                    continue
                fp = finding_fingerprint(f)
                if new_warn_fps[fp] > 0:
                    new_warns.append(f)
                    new_warn_fps[fp] -= 1

            if not errors and not new_warns:
                print("Baseline status: CLEAN — no ERROR and no new WARN findings")
            else:
                affected = sorted({f.source for f in errors + new_warns if f.source})
                print(f"URLs with new ERROR/WARN findings: {len(affected)}")
                for u in affected:
                    e = sum(1 for f in errors if f.source == u)
                    w = sum(1 for f in new_warns if f.source == u)
                    print(f"  {e}E {w} new-W  {u}")
                print("\nNew/critical findings:")
                for f in errors + new_warns:
                    loc = f"{f.source}:{f.line}" if f.source else f"line {f.line}"
                    print(f"{f.severity:5} {f.rule_id:12} {loc}  {f.message}")
                    if f.excerpt:
                        print(f"      {f.excerpt}")
        else:
            noisy = [p for p in report['per_page'] if p['ERROR'] or p['WARN'] or p['INFO']]
            print(f"URLs with findings: {len(noisy)} / {report['linted_urls']}")
            for p in noisy:
                print(f"  {p['ERROR']}E {p['WARN']}W {p['INFO']}I  {p['url']}")
            if findings:
                print("\nDetailed findings:")
                for f in findings:
                    loc = f"{f.source}:{f.line}" if f.source else f"line {f.line}"
                    print(f"{f.severity:5} {f.rule_id:12} {loc}  {f.message}")
                    if f.excerpt:
                        print(f"      {f.excerpt}")
        write_json_report(args.json_out, findings, report, baseline_diff)
        if auto_mode:
            new_warn_count = baseline_diff["counts"]["new_warn"] if baseline_diff is not None else counts["WARN"]
            action_required = counts["ERROR"] > 0 or new_warn_count > 0
            print("\n" + ("ACTION REQUIRED" if action_required else "CLEAN"))
            return 1 if action_required else 0
        return 1 if any(f.severity == "ERROR" for f in findings) else 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
