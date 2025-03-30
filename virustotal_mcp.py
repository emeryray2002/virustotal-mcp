# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import logging
import base64
import asyncio
from typing import Any, Dict, List, Optional, Union

import aiohttp
from mcp.server.fastmcp import FastMCP

# Initialize FastMCP server
mcp = FastMCP("virustotal-mcp")

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("virustotal-mcp")

# Constants
VT_API_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_RELATIONSHIP_LIMIT = 10
MAX_RELATIONSHIP_LIMIT = 40 # As per VirusTotal documentation for relationship endpoints

# Retrieve API Key from environment variable
VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY")

if not VT_API_KEY:
    logger.error("VIRUSTOTAL_API_KEY environment variable not set. Server cannot function.")
    # Optionally, you could raise an exception here or exit,
    # but allowing it to run might be useful for observing MCP behavior.
    # raise ValueError("VIRUSTOTAL_API_KEY environment variable not set.")

# --- Helper Functions ---

async def _make_vt_request(
    method: str,
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    custom_headers: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Makes an asynchronous request to the VirusTotal API."""
    if not VT_API_KEY:
        return {"error": "VirusTotal API key is not configured."}

    url = f"{VT_API_BASE_URL}/{endpoint.lstrip('/')}"
    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
        "User-Agent": "mcp-virustotal-server/1.0"
    }
    if custom_headers:
        headers.update(custom_headers)

    try:
        async with aiohttp.ClientSession(headers=headers) as session:
            logger.debug(f"Making VT Request: {method} {url} Params: {params} Data: {data}")
            async with session.request(method, url, params=params, json=data) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 204: # No content, often for relationships with no data
                    return {"data": []} # Return empty list structure
                elif response.status == 404:
                    logger.warning(f"VirusTotal resource not found: {url}")
                    return {"error": f"Resource not found: {response.reason}"}
                elif response.status == 401:
                    logger.error("VirusTotal API key unauthorized.")
                    return {"error": "Unauthorized. Check your API key."}
                elif response.status == 429:
                    logger.warning("VirusTotal rate limit exceeded.")
                    return {"error": "API rate limit exceeded. Please try again later."}
                else:
                    error_text = await response.text()
                    logger.error(f"VirusTotal API error {response.status}: {response.reason} - {error_text}")
                    return {"error": f"API Error {response.status}: {response.reason}", "details": error_text[:500]} # Limit details size
    except aiohttp.ClientError as e:
        logger.error(f"Network or connection error contacting VirusTotal: {e}", exc_info=True)
        return {"error": f"Network error: {e}"}
    except Exception as e:
        logger.error(f"An unexpected error occurred during VirusTotal request: {e}", exc_info=True)
        return {"error": f"An unexpected error occurred: {str(e)}"}

def get_vt_url_identifier(url: str) -> str:
    """
    Generates the VirusTotal URL identifier (URL-safe base64 without padding).
    See: https://docs.virustotal.com/reference/url
    """
    return base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()

async def _fetch_relationships(
    object_type: str,
    identifier: str,
    relationships: List[str],
    limit: int = 5 # Fetch a small number for combined reports
) -> Dict[str, Any]:
    """Fetches multiple relationships for a given object."""
    results = {}
    tasks = []
    for rel in relationships:
        endpoint = f"{object_type}/{identifier}/{rel}"
        params = {"limit": limit}
        tasks.append(_make_vt_request("GET", endpoint, params=params))

    relationship_responses = await asyncio.gather(*tasks)

    for rel, response in zip(relationships, relationship_responses):
        if "error" in response:
            logger.warning(f"Failed to fetch relationship '{rel}' for {object_type} {identifier}: {response['error']}")
            results[f"related_{rel}"] = {"error": response["error"]}
        elif "data" in response:
             # Check if data is a list (standard relationship response)
            if isinstance(response.get("data"), list):
                 results[f"related_{rel}"] = {
                     "count": len(response["data"]),
                     "items": response["data"],
                     "meta": response.get("meta") # Include cursor if present
                 }
            else:
                 # Handle cases where 'data' might not be a list (e.g., single object relationship)
                 results[f"related_{rel}"] = {
                     "count": 1 if response.get("data") else 0,
                     "items": [response["data"]] if response.get("data") else [],
                     "meta": response.get("meta")
                 }
        else:
             # Handle unexpected response structure
             results[f"related_{rel}"] = {"error": "Unexpected response format", "raw_response": response}


    return results

# --- VirusTotal Tools ---

## --- Comprehensive Report Tools (with Relationship Fetching) ---

@mcp.tool()
async def get_file_report(hash: str) -> Dict[str, Any]:
    """
    Name: get_file_report
    Description: Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships like behaviors, dropped files, network connections, embedded content, and related threat actors. This tool automatically fetches summary information for these key relationships. For detailed, paginated relationship data, use the 'get_file_relationship' tool.
    Parameters:
    hash (required): The MD5, SHA-1, or SHA-256 hash of the file to analyze. Example: '8ab2cf...', 'e4d909c290d0...', etc.
    """
    logger.info(f"Fetching comprehensive file report for hash: {hash}")
    endpoint = f"files/{hash}"
    report = await _make_vt_request("GET", endpoint)

    if "error" in report:
        logger.error(f"Error fetching main file report for {hash}: {report['error']}")
        return {"error": f"Failed to get main file report: {report['error']}", "details": report.get("details")}

    # Define key relationships to fetch automatically for files
    key_relationships = [
        "behaviours", "dropped_files", "contacted_domains", "contacted_ips",
        "contacted_urls", "embedded_domains", "embedded_ips", "embedded_urls",
        "related_threat_actors", "execution_parents", "compressed_parents"
    ]

    logger.info(f"Fetching related data for file {hash}: {key_relationships}")
    relationship_data = await _fetch_relationships("files", hash, key_relationships)

    # Combine the main report with relationship data
    combined_report = {"main_report": report}
    combined_report.update(relationship_data)

    logger.info(f"Successfully generated comprehensive file report for hash: {hash}")
    return combined_report

@mcp.tool()
async def get_url_report(url: str) -> Dict[str, Any]:
    """
    Name: get_url_report
    Description: Get a comprehensive URL analysis report including security scan results and key relationships like communicating files, contacted domains/IPs, downloaded files, redirects, and related threat actors. This tool automatically fetches summary information for these key relationships. For detailed, paginated relationship data, use the 'get_url_relationship' tool.
    Parameters:
    url (required): The URL to analyze (e.g., 'http://example.com/badsite', 'https://google.com'). The tool will automatically generate the required VirusTotal URL identifier.
    """
    logger.info(f"Fetching comprehensive URL report for: {url}")
    try:
        url_id = get_vt_url_identifier(url)
        logger.info(f"Generated URL ID: {url_id}")
    except Exception as e:
        logger.error(f"Error generating URL ID for {url}: {e}")
        return {"error": f"Failed to generate VirusTotal ID for the URL: {e}"}

    endpoint = f"urls/{url_id}"
    report = await _make_vt_request("GET", endpoint)

    if "error" in report:
        logger.error(f"Error fetching main URL report for {url} (ID: {url_id}): {report['error']}")
        return {"error": f"Failed to get main URL report: {report['error']}", "details": report.get("details")}

    # Define key relationships to fetch automatically for URLs
    key_relationships = [
        "communicating_files", "contacted_domains", "contacted_ips",
        "downloaded_files", "redirects_to", "related_threat_actors",
        "last_serving_ip_address", "network_location"
    ]

    logger.info(f"Fetching related data for URL {url} (ID: {url_id}): {key_relationships}")
    relationship_data = await _fetch_relationships("urls", url_id, key_relationships)

    # Combine the main report with relationship data
    combined_report = {"main_report": report}
    combined_report.update(relationship_data)

    logger.info(f"Successfully generated comprehensive URL report for: {url}")
    return combined_report

@mcp.tool()
async def get_domain_report(domain: str) -> Dict[str, Any]:
    """
    Name: get_domain_report
    Description: Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships like historical SSL certificates, subdomains, resolutions, and related threat actors. This tool automatically fetches summary information for these key relationships. For detailed, paginated relationship data, use the 'get_domain_relationship' tool.
    Parameters:
    domain (required): The domain name to analyze (e.g., 'google.com', 'evil-domain.net').
    """
    logger.info(f"Fetching comprehensive domain report for: {domain}")
    endpoint = f"domains/{domain}"
    report = await _make_vt_request("GET", endpoint)

    if "error" in report:
        logger.error(f"Error fetching main domain report for {domain}: {report['error']}")
        return {"error": f"Failed to get main domain report: {report['error']}", "details": report.get("details")}

    # Define key relationships to fetch automatically for domains
    key_relationships = [
        "historical_ssl_certificates", "historical_whois", "resolutions",
        "siblings", "subdomains", "related_threat_actors", "urls",
        "communicating_files", "downloaded_files"
    ]

    logger.info(f"Fetching related data for domain {domain}: {key_relationships}")
    relationship_data = await _fetch_relationships("domains", domain, key_relationships)

    # Combine the main report with relationship data
    combined_report = {"main_report": report}
    combined_report.update(relationship_data)

    logger.info(f"Successfully generated comprehensive domain report for: {domain}")
    return combined_report

@mcp.tool()
async def get_ip_report(ip: str) -> Dict[str, Any]:
    """
    Name: get_ip_report
    Description: Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships like communicating/downloaded files, historical certificates/WHOIS, resolutions, and related URLs/threat actors. This tool automatically fetches summary information for these key relationships. For detailed, paginated relationship data, use the 'get_ip_relationship' tool.
    Parameters:
    ip (required): The IP address to analyze (e.g., '8.8.8.8', '192.168.1.1').
    """
    logger.info(f"Fetching comprehensive IP address report for: {ip}")
    endpoint = f"ip_addresses/{ip}"
    report = await _make_vt_request("GET", endpoint)

    if "error" in report:
        logger.error(f"Error fetching main IP report for {ip}: {report['error']}")
        return {"error": f"Failed to get main IP report: {report['error']}", "details": report.get("details")}

    # Define key relationships to fetch automatically for IPs
    key_relationships = [
        "communicating_files", "downloaded_files", "historical_ssl_certificates",
        "historical_whois", "resolutions", "urls", "related_threat_actors"
    ]

    logger.info(f"Fetching related data for IP {ip}: {key_relationships}")
    relationship_data = await _fetch_relationships("ip_addresses", ip, key_relationships)

    # Combine the main report with relationship data
    combined_report = {"main_report": report}
    combined_report.update(relationship_data)

    logger.info(f"Successfully generated comprehensive IP report for: {ip}")
    return combined_report


## --- Specific Data Point Tools ---

@mcp.tool()
async def get_file_behavior_summary(hash: str) -> Dict[str, Any]:
    """
    Name: get_file_behavior_summary
    Description: Retrieves a summary of all behavior reports (sandbox execution details) for a specific file hash (MD5/SHA-1/SHA-256). This provides a consolidated view of dynamic analysis results from multiple sandboxes.
    Parameters:
    hash (required): The MD5, SHA-1, or SHA-256 hash of the file.
    """
    logger.info(f"Fetching file behavior summary for hash: {hash}")
    endpoint = f"files/{hash}/behaviours_summary" # Note the plural 'behaviours'
    result = await _make_vt_request("GET", endpoint)

    if "error" in result:
        logger.error(f"Error fetching behavior summary for {hash}: {result['error']}")

    return result

@mcp.tool()
async def advanced_corpus_search(
    query: str,
    limit: int = 20,
    cursor: Optional[str] = None,
    descriptors_only: Optional[bool] = None
) -> Dict[str, Any]:
    """
    Name: advanced_corpus_search
    Description: Performs an advanced search across the VirusTotal dataset using VT Intelligence query syntax. This requires a premium VirusTotal API key with Intelligence access. Supports pagination.
    Parameters:
    query (required): The VT Intelligence search query string. Examples: 'p:mimikatz', 'type:peexe size:100kb+ positives:5+', 'entity:url url:"example.com"'. See VT documentation for syntax.
    limit (optional, default: 20): Maximum number of results to return per page (max usually 300 for intelligence).
    cursor (optional): Continuation cursor for pagination, obtained from the 'meta.cursor' field of a previous response.
    descriptors_only (optional): If true, retrieves only object descriptors (e.g., SHA256 hashes for files) instead of full objects, which can be faster.
    """
    logger.info(f"Performing advanced VirusTotal search: {query} (Limit: {limit}, Cursor: {cursor})")
    endpoint = "intelligence/search"
    params: Dict[str, Any] = {"query": query, "limit": limit}
    if cursor:
        params["cursor"] = cursor
    if descriptors_only is not None:
         params["descriptors_only"] = str(descriptors_only).lower() # API expects string 'true'/'false'

    result = await _make_vt_request("GET", endpoint, params=params)

    if "error" in result:
        logger.error(f"Error performing advanced search '{query}': {result['error']}")
    elif not result.get('data') and not result.get('meta'):
         # Handle cases where the API might return empty success (e.g., no matches)
         return {"message": "Search completed, no matching results found.", "query": query}


    return result

## --- Detailed Relationship Tools (with Pagination) ---

@mcp.tool()
async def get_file_relationship(
    hash: str,
    relationship: str,
    limit: int = DEFAULT_RELATIONSHIP_LIMIT,
    cursor: Optional[str] = None
) -> Dict[str, Any]:
    """
    Name: get_file_relationship
    Description: Query a specific relationship type for a file hash (MD5/SHA-1/SHA-256) with pagination support. Use this for in-depth exploration of connections.
    Parameters:
    hash (required): MD5, SHA-1 or SHA-256 hash of the file.
    relationship (required): Type of relationship to query. Choose from: analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, ciphered_bundled_files, ciphered_parents, clues, collections, comments, compressed_parents, contacted_domains, contacted_ips, contacted_urls, dropped_files, email_attachments, email_parents, embedded_domains, embedded_ips, embedded_urls, execution_parents, graphs, itw_domains, itw_ips, itw_urls, memory_pattern_domains, memory_pattern_ips, memory_pattern_urls, overlay_children, overlay_parents, pcap_children, pcap_parents, pe_resource_children, pe_resource_parents, related_references, related_threat_actors, similar_files, submissions, screenshots, urls_for_embedded_js, votes.
    limit (optional, default: 10): Maximum number of related objects to retrieve per page (1-40).
    cursor (optional): Continuation cursor from previous page's 'meta.cursor' for pagination.
    """
    logger.info(f"Fetching relationship '{relationship}' for file {hash} (Limit: {limit}, Cursor: {cursor})")
    # Validate limit
    limit = max(1, min(limit, MAX_RELATIONSHIP_LIMIT))
    endpoint = f"files/{hash}/{relationship}"
    params: Dict[str, Union[str, int]] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    result = await _make_vt_request("GET", endpoint, params=params)

    if "error" in result:
        logger.error(f"Error fetching relationship {relationship} for file {hash}: {result['error']}")

    return result


@mcp.tool()
async def get_url_relationship(
    url: str,
    relationship: str,
    limit: int = DEFAULT_RELATIONSHIP_LIMIT,
    cursor: Optional[str] = None
) -> Dict[str, Any]:
    """
    Name: get_url_relationship
    Description: Query a specific relationship type for a URL with pagination support. Use this for in-depth exploration of connections. The tool automatically generates the required VirusTotal URL identifier.
    Parameters:
    url (required): The URL to get relationships for.
    relationship (required): Type of relationship to query. Choose from: analyses, comments, communicating_files, contacted_domains, contacted_ips, downloaded_files, graphs, last_serving_ip_address, network_location, referrer_files, referrer_urls, redirecting_urls, redirects_to, related_comments, related_references, related_threat_actors, submissions.
    limit (optional, default: 10): Maximum number of related objects to retrieve per page (1-40).
    cursor (optional): Continuation cursor from previous page's 'meta.cursor' for pagination.
    """
    logger.info(f"Fetching relationship '{relationship}' for URL {url} (Limit: {limit}, Cursor: {cursor})")
    try:
        url_id = get_vt_url_identifier(url)
    except Exception as e:
        logger.error(f"Error generating URL ID for {url}: {e}")
        return {"error": f"Failed to generate VirusTotal ID for the URL: {e}"}

    # Validate limit
    limit = max(1, min(limit, MAX_RELATIONSHIP_LIMIT))
    endpoint = f"urls/{url_id}/{relationship}"
    params: Dict[str, Union[str, int]] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    result = await _make_vt_request("GET", endpoint, params=params)

    if "error" in result:
        logger.error(f"Error fetching relationship {relationship} for URL {url} (ID: {url_id}): {result['error']}")

    return result

@mcp.tool()
async def get_domain_relationship(
    domain: str,
    relationship: str,
    limit: int = DEFAULT_RELATIONSHIP_LIMIT,
    cursor: Optional[str] = None
) -> Dict[str, Any]:
    """
    Name: get_domain_relationship
    Description: Query a specific relationship type for a domain with pagination support. Use this for in-depth exploration of connections.
    Parameters:
    domain (required): The domain name to analyze.
    relationship (required): Type of relationship to query. Choose from: caa_records, cname_records, comments, communicating_files, downloaded_files, historical_ssl_certificates, historical_whois, immediate_parent, mx_records, ns_records, parent, referrer_files, related_comments, related_references, related_threat_actors, resolutions, soa_records, siblings, subdomains, urls, user_votes.
    limit (optional, default: 10): Maximum number of related objects to retrieve per page (1-40).
    cursor (optional): Continuation cursor from previous page's 'meta.cursor' for pagination.
    """
    logger.info(f"Fetching relationship '{relationship}' for domain {domain} (Limit: {limit}, Cursor: {cursor})")
    # Validate limit
    limit = max(1, min(limit, MAX_RELATIONSHIP_LIMIT))
    endpoint = f"domains/{domain}/{relationship}"
    params: Dict[str, Union[str, int]] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    result = await _make_vt_request("GET", endpoint, params=params)

    if "error" in result:
        logger.error(f"Error fetching relationship {relationship} for domain {domain}: {result['error']}")

    return result

@mcp.tool()
async def get_ip_relationship(
    ip: str,
    relationship: str,
    limit: int = DEFAULT_RELATIONSHIP_LIMIT,
    cursor: Optional[str] = None
) -> Dict[str, Any]:
    """
    Name: get_ip_relationship
    Description: Query a specific relationship type for an IP address with pagination support. Use this for in-depth exploration of connections.
    Parameters:
    ip (required): The IP address to analyze.
    relationship (required): Type of relationship to query. Choose from: comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, related_comments, related_references, related_threat_actors, referrer_files, resolutions, urls.
    limit (optional, default: 10): Maximum number of related objects to retrieve per page (1-40).
    cursor (optional): Continuation cursor from previous page's 'meta.cursor' for pagination.
    """
    logger.info(f"Fetching relationship '{relationship}' for IP {ip} (Limit: {limit}, Cursor: {cursor})")
    # Validate limit
    limit = max(1, min(limit, MAX_RELATIONSHIP_LIMIT))
    endpoint = f"ip_addresses/{ip}/{relationship}"
    params: Dict[str, Union[str, int]] = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    result = await _make_vt_request("GET", endpoint, params=params)

    if "error" in result:
        logger.error(f"Error fetching relationship {relationship} for IP {ip}: {result['error']}")

    return result

# --- Main Execution ---

def main() -> None:
    """Run the MCP server for VirusTotal tools."""
    if not VT_API_KEY:
        logger.error("VIRUSTOTAL_API_KEY environment variable not set. MCP server cannot start.")
        return

    logger.info("Starting VirusTotal MCP server...")
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()