import requests
import json
from pyfiglet import Figlet
from colorama import Fore, Style, init
from tqdm import tqdm
import time
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from ratelimit import limits, sleep_and_retry
import argparse
import os
import csv
from datetime import datetime
from urllib.parse import urlparse
import plotly.graph_objs as go
import plotly.offline as pyo
import logging
from requests.exceptions import RequestException, HTTPError, ConnectionError, Timeout
import validators

# Initialize colorama for cross-platform colored terminal text
init(autoreset=True)

# Constants for rate limiting
FIFTEEN_MINUTES = 900
REQUESTS_PER_FIFTEEN_MINUTES = 60  # Adjusted to be more conservative

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class JusDoorkin:
    """
    A class for performing Google dorking and analyzing results.

    This class provides methods for generating and executing Google dork queries,
    analyzing the results, and generating reports.
    """

    def __init__(self, output_dir="results"):
        """
        Initialize the JusDoorkin object.

        Args:
            output_dir (str): The directory to store results and reports.
        """
        self.patterns = {
            "backlink": 'link:{domain} -site:{domain}',
            "subdomain": 'site:*.{domain} -site:www.{domain}',
            "email": '"*@{domain}" -www.{domain}',
            "admin_url": 'site:{domain} inurl:admin||login||user',
            "documents": 'site:{domain} filetype:pdf||doc||xls||ppt||docx||xlsx||pptx',
            "config_files": 'site:{domain} filetype:xml||conf||cfg||ini',
            "sql_errors": 'site:{domain} intext:"sql syntax"||"syntax error"',
            "directory_listing": 'site:{domain} intitle:index.of',
            "exposed_databases": 'site:{domain} intext:"sql dump" filetype:sql',
            "api_endpoints": 'site:{domain} inurl:api',
            "cloud_storage": 'site:{domain} (inurl:s3.amazonaws.com | inurl:storage.googleapis.com | inurl:azure)',
            "social_media": 'site:{domain} (inurl:facebook | inurl:twitter | inurl:linkedin | inurl:instagram)',
            "wordpress_files": 'site:{domain} inurl:wp-content | inurl:wp-includes',
        }
        self.search_engines = {
            "google": "https://www.google.com/search?q={query}&num=100",
            "bing": "https://www.bing.com/search?q={query}&count=50",
            "duckduckgo": "https://html.duckduckgo.com/html/?q={query}"
        }
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_query(self, domain, query_type):
        """
        Generate a Google dork query for a given domain and query type.

        Args:
            domain (str): The target domain.
            query_type (str): The type of query to generate.

        Returns:
            str: The generated query.
        """
        return self.patterns[query_type].format(domain=domain)

    @sleep_and_retry
    @limits(calls=REQUESTS_PER_FIFTEEN_MINUTES, period=FIFTEEN_MINUTES)
    def search_query(self, query, query_type, domain, engine="google"):
        """
        Execute a search query and process the results.

        Args:
            query (str): The search query to execute.
            query_type (str): The type of query being executed.
            domain (str): The target domain.
            engine (str): The search engine to use.

        Returns:
            list or str: The processed search results.
        """
        url = self.search_engines[engine].format(query=query)
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}

        max_retries = 3
        backoff_factor = 2
        for attempt in range(max_retries):
            try:
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                break
            except RequestException as e:
                logger.warning(f"Request failed (attempt {attempt + 1}/{max_retries}): {str(e)}")
                if attempt == max_retries - 1:
                    logger.error(f"Max retries reached for query: {query}")
                    return f"Error: {str(e)}"
                time.sleep(backoff_factor ** attempt)
        else:
            logger.error(f"Failed to execute query after {max_retries} attempts: {query}")
            return "Error: Max retries reached"

        if query_type in ["subdomain", "email", "admin_url", "directory_listing", "exposed_databases", "api_endpoints", "cloud_storage"]:
            pattern = rf'https?://[a-zA-Z0-9.-]*{re.escape(domain)}[^\s"\'<>]+'
            if query_type == "email":
                pattern = rf'[a-zA-Z0-9._%+-]+@{re.escape(domain)}'
            items = re.findall(pattern, response.text)
            return list(set(items))
        else:
            result_stats_match = re.search(r'About (.+?) results', response.text)
            return result_stats_match.group(1) if result_stats_match else 'Unknown'

    def perform_dork_scan(self, domains, query_types=None, engines=None):
        """
        Perform a dork scan on the specified domains.

        Args:
            domains (list): List of domains to scan.
            query_types (list): List of query types to use.
            engines (list): List of search engines to use.

        Returns:
            dict: The scan results.
        """
        results = {domain: {} for domain in domains}
        queries = self.patterns if query_types is None else {qt: self.patterns[qt] for qt in query_types}
        engines = engines or ["google"]

        def worker(domain, query_type, engine):
            query = self.generate_query(domain, query_type)
            result = self.search_query(query, query_type, domain, engine)
            return domain, query_type, engine, result

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for domain in domains:
                for query_type in queries:
                    for engine in engines:
                        futures.append(executor.submit(worker, domain, query_type, engine))

            for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning", ncols=70):
                domain, query_type, engine, result = future.result()
                if engine not in results[domain]:
                    results[domain][engine] = {}
                results[domain][engine][query_type] = result
                time.sleep(random.uniform(1, 3))

        return results

    def analyze_results(self, results):
        """
        Analyze the scan results to identify potential vulnerabilities and interesting findings.

        Args:
            results (dict): The scan results to analyze.

        Returns:
            dict: The analysis results.
        """
        analysis = {}
        for domain, engines in results.items():
            analysis[domain] = {
                "total_subdomains": 0,
                "total_emails": 0,
                "potential_vulnerabilities": [],
                "interesting_files": [],
                "exposed_endpoints": [],
            }
            for engine, data in engines.items():
                analysis[domain]["total_subdomains"] += len(data.get("subdomain", []))
                analysis[domain]["total_emails"] += len(data.get("email", []))

                if data.get("sql_errors"):
                    analysis[domain]["potential_vulnerabilities"].append("SQL Injection")
                if data.get("directory_listing"):
                    analysis[domain]["potential_vulnerabilities"].append("Directory Listing")
                if data.get("config_files"):
                    analysis[domain]["interesting_files"].extend(data.get("config_files", []))
                if data.get("exposed_databases"):
                    analysis[domain]["potential_vulnerabilities"].append("Exposed Database Dumps")
                if data.get("api_endpoints"):
                    analysis[domain]["exposed_endpoints"].extend(data.get("api_endpoints", []))
                
                # Additional checks
                if data.get("admin_url"):
                    analysis[domain]["potential_vulnerabilities"].append("Exposed Admin Interfaces")
                if data.get("documents"):
                    analysis[domain]["interesting_files"].extend(data.get("documents", []))
                if data.get("cloud_storage"):
                    analysis[domain]["potential_vulnerabilities"].append("Exposed Cloud Storage")
                if data.get("wordpress_files"):
                    analysis[domain]["potential_vulnerabilities"].append("WordPress Installation")

        return analysis

    def generate_report(self, results, analysis):
        """
        Generate an HTML report of the scan results and analysis.

        Args:
            results (dict): The scan results.
            analysis (dict): The analysis of the scan results.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(self.output_dir, f"report_{timestamp}.html")

        with open(report_file, 'w') as f:
            f.write("""
            <html>
            <head>
                <title>JusDoorkin Scan Report</title>
                <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
                <style>
                    body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f0f0f0; }
                    .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                    h1, h2, h3, h4, h5 { color: #333; }
                    .chart { width: 100%; height: 400px; margin-bottom: 20px; }
                    table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>JusDoorkin Scan Report</h1>
            """)

            # Create a bar chart for subdomain and email counts
            domains = list(analysis.keys())
            subdomain_counts = [analysis[domain]['total_subdomains'] for domain in domains]
            email_counts = [analysis[domain]['total_emails'] for domain in domains]

            trace1 = go.Bar(x=domains, y=subdomain_counts, name='Subdomains')
            trace2 = go.Bar(x=domains, y=email_counts, name='Emails')
            layout = go.Layout(title='Subdomain and Email Counts', barmode='group')
            fig = go.Figure(data=[trace1, trace2], layout=layout)
            plot_div = pyo.plot(fig, output_type='div', include_plotlyjs=False)

            f.write(f'<div class="chart" id="subdomain-email-chart">{plot_div}</div>')

            for domain, domain_analysis in analysis.items():
                f.write(f"<h2>Domain: {domain}</h2>")
                f.write(f"<p>Total Subdomains: {domain_analysis['total_subdomains']}</p>")
                f.write(f"<p>Total Emails: {domain_analysis['total_emails']}</p>")

                if domain_analysis['potential_vulnerabilities']:
                    f.write("<h3>Potential Vulnerabilities:</h3><ul>")
                    for vuln in domain_analysis['potential_vulnerabilities']:
                        f.write(f"<li>{vuln}</li>")
                    f.write("</ul>")

                if domain_analysis['interesting_files']:
                    f.write("<h3>Interesting Files:</h3><ul>")
                    for file in domain_analysis['interesting_files'][:10]:  # Limit to first 10
                        f.write(f"<li>{file}</li>")
                    f.write("</ul>")

                if domain_analysis['exposed_endpoints']:
                    f.write("<h3>Exposed Endpoints:</h3><ul>")
                    for endpoint in domain_analysis['exposed_endpoints'][:10]:  # Limit to first 10
                        f.write(f"<li>{endpoint}</li>")
                    f.write("</ul>")

                f.write("<h3>Detailed Results:</h3>")
                for engine, engine_data in results[domain].items():
                    f.write(f"<h4>Engine: {engine}</h4>")
                    f.write("<table><tr><th>Query Type</th><th>Result</th></tr>")
                    for query_type, result in engine_data.items():
                        f.write(f"<tr><td>{query_type}</td><td>")
                        if isinstance(result, list):
                            f.write("<ul>")
                            for item in result[:20]:  # Limit to first 20 items
                                f.write(f"<li>{item}</li>")
                            if len(result) > 20:
                                f.write(f"<li>... and {len(result) - 20} more</li>")
                            f.write("</ul>")
                        else:
                            f.write(f"{result}")
                        f.write("</td></tr>")
                    f.write("</table>")

            f.write("</div></body></html>")

        logger.info(f"Report generated: {report_file}")

def print_banner():
    """Print the JusDoorkin banner."""
    f = Figlet(font='col')
    print(Fore.CYAN + f.renderText('JusDoorkin'))
    print(Fore.YELLOW + "Advanced Google Dork Query Generator" + Style.RESET_ALL)
    print(Fore.RED + "Use responsibly and ethically. Don't perform scans without permission." + Style.RESET_ALL)
    print("\nThis tool generates Google dork queries to find potentially sensitive information about specified domains.")
    print()

def get_domains():
    """
    Get domain input from the user.

    Returns:
        list: List of domains to scan.
    """
    while True:
        try:
            domains = [domain.strip() for domain in input("Enter domain(s) to scan (separate multiple domains with commas): ").split(',')]
            if not domains or any(not validators.domain(domain) for domain in domains):
                raise ValueError("Invalid input. Please enter valid domain names.")
            return domains
        except ValueError as e:
            print(Fore.RED + str(e) + Style.RESET_ALL)

def get_query_types(dorker):
    """
    Get query types from the user.

    Args:
        dorker (JusDoorkin): The JusDoorkin object.

    Returns:
        list or None: List of query types to use, or None for all types.
    """
    print("\nAvailable query types:")
    for i, query_type in enumerate(dorker.patterns.keys(), 1):
        print(f"{i}. {query_type}")
    print("0. All query types")

    while True:
        try:
            choice = input("\nEnter the numbers of query types you want to use (comma-separated), or 0 for all: ")
            if choice == '0':
                return None
            choices = [int(c.strip()) for c in choice.split(',')]
            if not all(1 <= c <= len(dorker.patterns) for c in choices):
                raise ValueError("Invalid choices. Please enter valid numbers.")
            return [list(dorker.patterns.keys())[c-1] for c in choices]
        except ValueError as e:
            print(Fore.RED + str(e) + Style.RESET_ALL)

def get_search_engines(dorker):
    """
    Get search engines from the user.

    Args:
        dorker (JusDoorkin): The JusDoorkin object.

    Returns:
        list: List of search engines to use.
    """
    print("\nAvailable search engines:")
    for i, engine in enumerate(dorker.search_engines.keys(), 1):
        print(f"{i}. {engine}")

    while True:
        try:
            choice = input("\nEnter the numbers of search engines you want to use (comma-separated): ")
            choices = [int(c.strip()) for c in choice.split(',')]
            if not all(1 <= c <= len(dorker.search_engines) for c in choices):
                raise ValueError("Invalid choices. Please enter valid numbers.")
            return [list(dorker.search_engines.keys())[c-1] for c in choices]
        except ValueError as e:
            print(Fore.RED + str(e) + Style.RESET_ALL)

def main():
    """Main function to run the JusDoorkin tool."""
    print_banner()

    parser = argparse.ArgumentParser(description="JusDoorkin - Advanced Google Dork Query Generator")
    parser.add_argument("-o", "--output", help="Specify output directory", default="results")
    args = parser.parse_args()

    dorker = JusDoorkin(output_dir=args.output)

    domains = get_domains()
    query_types = get_query_types(dorker)
    engines = get_search_engines(dorker)

    print(Fore.CYAN + "\nStarting scan..." + Style.RESET_ALL)
    results = dorker.perform_dork_scan(domains, query_types, engines)

    print(Fore.CYAN + "\nAnalyzing results..." + Style.RESET_ALL)
    analysis = dorker.analyze_results(results)

    print(Fore.CYAN + "\nGenerating report..." + Style.RESET_ALL)
    dorker.generate_report(results, analysis)

    print(Fore.GREEN + "\nScan completed. Check the results directory for the report." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
