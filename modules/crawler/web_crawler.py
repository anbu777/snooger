"""
Web crawler: extracts links, forms, parameters, and JS endpoints.
"""
import os
import re
import logging
import requests
from urllib.parse import urljoin, urlparse, parse_qs
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from typing import List, Set, Dict, Optional
from core.rate_limiter import get_rate_limiter
from core.utils import random_user_agent, write_json

logger = logging.getLogger('snooger')

class WebCrawler:
    def __init__(self, base_url: str, auth=None, max_pages: int = 200,
                 max_depth: int = 3, scope=None, config = None):
        self.base_url = base_url.rstrip('/')
        self.base_domain = urlparse(base_url).netloc
        self.auth = auth
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.scope = scope
        self.config = config or {}
        self.rl = get_rate_limiter()

        self.visited: Set[str] = set()
        self.forms: List[dict] = []
        self.links: Set[str] = set()
        self.js_files: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}  # param_name -> set of URLs

        if auth:
            self.session = auth.session
        else:
            self.session = requests.Session()
            self.session.headers.update({'User-Agent': random_user_agent()})

    def crawl(self, start_url: Optional[str] = None) -> dict:
        """BFS crawl starting from start_url."""
        url = start_url or self.base_url
        queue = [(url, 0)]

        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.pop(0)
            if current_url in self.visited or depth > self.max_depth:
                continue

            # Scope check
            if self.scope and not self.scope.is_in_scope(current_url):
                continue

            self.visited.add(current_url)
            logger.debug(f"Crawling [{depth}]: {current_url}")

            try:
                self.rl.wait(self.base_domain)
                resp = self.session.get(current_url, timeout=10,
                                        allow_redirects=True, verify=False)
                if resp.status_code == 200:
                    new_urls = self._extract_links(current_url, resp.text, dict(resp.headers))
                    self._extract_forms(current_url, resp.text)
                    self._extract_parameters(current_url)

                    for new_url in new_urls:
                        if new_url not in self.visited:
                            queue.append((new_url, depth + 1))

                    if resp.status_code in (429, 503):
                        self.rl.penalize(self.base_domain)
            except Exception as e:
                logger.debug(f"Crawl error {current_url}: {e}")

        return self._build_result()

    def _extract_links(self, base_url: str, html: str, headers: dict) -> Set[str]:
        """Extract all links from HTML."""
        new_links = set()
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')

        for tag in soup.find_all(['a', 'link', 'area']):
            href = tag.get('href', '')
            if href:
                abs_url = urljoin(base_url, str(href))
                abs_url = abs_url.split('#')[0]  # Remove fragments
                parsed = urlparse(abs_url)
                if parsed.scheme in ('http', 'https') and self.base_domain in parsed.netloc:
                    self.links.add(abs_url)
                    new_links.add(abs_url)

        for tag in soup.find_all('script'):
            src = tag.get('src', '')
            if src:
                abs_src = urljoin(base_url, str(src))
                if abs_src.endswith('.js'):
                    self.js_files.add(abs_src)

        # Extract from JavaScript inline
        js_urls = re.findall(r'["\']((?:https?://[^"\']+|/[a-zA-Z0-9/\-_.?=&]+))["\']', html)
        for url in js_urls:
            if url.startswith('/'):
                abs_url = urljoin(base_url, url)
                if self.base_domain in abs_url:
                    new_links.add(abs_url)
                    self.links.add(abs_url)
            elif url.startswith('http') and self.base_domain in url:
                new_links.add(url)

        # Check for API endpoints
        api_patterns = re.findall(
            r'["\'](/(?:api|v\d+|rest|graphql|endpoint)[^"\']*)["\']', html
        )
        for ep in api_patterns:
            self.api_endpoints.add(urljoin(base_url, ep))

        return new_links

    def _extract_forms(self, url: str, html: str) -> None:
        """Extract forms with their inputs for testing."""
        try:
            soup = BeautifulSoup(html, 'lxml')
        except Exception:
            soup = BeautifulSoup(html, 'html.parser')

        for form in soup.find_all('form'):
            action = form.get('action', url)
            method = str(form.get('method', 'GET')).upper()
            form_url = urljoin(url, str(action))

            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_name = inp.get('name', '')
                inp_type = inp.get('type', 'text')
                inp_value = inp.get('value', '')
                if inp_name:
                    inputs.append({
                        'name': inp_name,
                        'type': inp_type,
                        'value': inp_value
                    })

            if inputs:
                self.forms.append({
                    'url': url,
                    'action': form_url,
                    'method': method,
                    'inputs': inputs
                })

    def _extract_parameters(self, url: str) -> None:
        """Track parameter names for targeted testing."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            if param not in self.parameters:
                self.parameters[param] = set()
            self.parameters[param].add(url)

    def _build_result(self) -> dict:
        return {
            'visited_urls': list(self.visited),
            'all_links': list(self.links),
            'js_files': list(self.js_files),
            'forms': self.forms,
            'api_endpoints': list(self.api_endpoints),
            'parameters': {k: list(v) for k, v in self.parameters.items()},
            'stats': {
                'pages_crawled': len(self.visited),
                'links_found': len(self.links),
                'forms_found': len(self.forms),
                'js_files': len(self.js_files),
                'api_endpoints': len(self.api_endpoints),
            }
        }

def crawl_target(target: str, workspace_dir: str, auth=None,
                 scope=None, config = None) -> dict:
    """Crawl a target and save results."""
    max_pages = (config or {}).get('_profile', {}).get('max_pages', 200)
    crawler = WebCrawler(target, auth=auth, max_pages=max_pages, scope=scope, config=config)
    results = crawler.crawl()
    write_json(os.path.join(workspace_dir, 'crawler_results.json'), results)
    logger.info(f"Crawl complete: {results['stats']}")
    return results
