# VirusTotal MCP Server
[![smithery badge](https://smithery.ai/badge/@emeryray2002/virustotal-mcp)](https://smithery.ai/server/@emeryray2002/virustotal-mcp)

A Model Context Protocol (MCP) server for querying the [VirusTotal API](https://www.virustotal.com/). This server provides comprehensive security analysis tools with automatic relationship data fetching. It integrates seamlessly with MCP-compatible applications like [Claude Desktop](https://claude.ai).

## Quick Start (TBD)

### Installing via Smithery

To install virustotal-mcp for Claude Desktop automatically via [Smithery](https://smithery.ai/server/@emeryray2002/virustotal-mcp):

```bash
npx -y @smithery/cli install @emeryray2002/virustotal-mcp --client claude
```

### Installing Manually
TBD

## Features

- **Comprehensive Analysis Reports**: Each analysis tool automatically fetches relevant relationship data along with the basic report, providing a complete security overview in a single request
- **URL Analysis**: Security reports with automatic fetching of contacted domains, downloaded files, and threat actors
- **File Analysis**: Detailed analysis of file hashes including behaviors, dropped files, and network connections
- **IP Analysis**: Security reports with historical data, resolutions, and related threats
- **Domain Analysis**: DNS information, WHOIS data, SSL certificates, and subdomains
- **Detailed Relationship Analysis**: Dedicated tools for querying specific types of relationships with pagination support
- **Advanced Search**: VT Intelligence search capabilities for complex queries across the VirusTotal dataset
- **Rich Formatting**: Clear categorization and presentation of analysis results and relationship data

## Tools

### Report Tools (with Automatic Relationship Fetching)

### 1. URL Report Tool
- Name: `get_url_report`
- Description: Get a comprehensive URL analysis report including security scan results and key relationships (communicating files, contacted domains/IPs, downloaded files, redirects, threat actors)
- Parameters:
  * `url` (required): The URL to analyze
- Example:
```python
await get_url_report(url="http://example.com/suspicious")
```

### 2. File Report Tool
- Name: `get_file_report`
- Description: Get a comprehensive file analysis report using its hash (MD5/SHA-1/SHA-256). Includes detection results, file properties, and key relationships (behaviors, dropped files, network connections, embedded content, threat actors)
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file
- Example:
```python
await get_file_report(hash="44d88612fea8a8f36de82e1278abb02f")
```

### 3. IP Report Tool
- Name: `get_ip_report`
- Description: Get a comprehensive IP address analysis report including geolocation, reputation data, and key relationships (communicating files, historical certificates/WHOIS, resolutions)
- Parameters:
  * `ip` (required): IP address to analyze
- Example:
```python
await get_ip_report(ip="8.8.8.8")
```

### 4. Domain Report Tool
- Name: `get_domain_report`
- Description: Get a comprehensive domain analysis report including DNS records, WHOIS data, and key relationships (SSL certificates, subdomains, historical data)
- Parameters:
  * `domain` (required): Domain name to analyze
- Example:
```python
await get_domain_report(domain="example.com")
```

### Relationship Tools (for Detailed Analysis)

### 1. URL Relationship Tool
- Name: `get_url_relationship`
- Description: Query a specific relationship type for a URL with pagination support
- Parameters:
  * `url` (required): The URL to get relationships for
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, comments, communicating_files, contacted_domains, contacted_ips, downloaded_files, graphs, last_serving_ip_address, network_location, referrer_files, referrer_urls, redirecting_urls, redirects_to, related_comments, related_references, related_threat_actors, submissions
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination
- Example:
```python
await get_url_relationship(
    url="http://example.com/suspicious",
    relationship="communicating_files",
    limit=20
)
```

### 2. File Relationship Tool
- Name: `get_file_relationship`
- Description: Query a specific relationship type for a file with pagination support
- Parameters:
  * `hash` (required): MD5, SHA-1 or SHA-256 hash of the file
  * `relationship` (required): Type of relationship to query
    - Available relationships: analyses, behaviours, bundled_files, carbonblack_children, carbonblack_parents, ciphered_bundled_files, ciphered_parents, clues, collections, comments, compressed_parents, contacted_domains, contacted_ips, contacted_urls, dropped_files, email_attachments, email_parents, embedded_domains, embedded_ips, embedded_urls, execution_parents, graphs, itw_domains, itw_ips, itw_urls, memory_pattern_domains, memory_pattern_ips, memory_pattern_urls, overlay_children, overlay_parents, pcap_children, pcap_parents, pe_resource_children, pe_resource_parents, related_references, related_threat_actors, similar_files, submissions, screenshots, urls_for_embedded_js, votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination
- Example:
```python
await get_file_relationship(
    hash="44d88612fea8a8f36de82e1278abb02f",
    relationship="behaviours",
    limit=20
)
```

### 3. IP Relationship Tool
- Name: `get_ip_relationship`
- Description: Query a specific relationship type for an IP address with pagination support
- Parameters:
  * `ip` (required): IP address to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: comments, communicating_files, downloaded_files, graphs, historical_ssl_certificates, historical_whois, related_comments, related_references, related_threat_actors, referrer_files, resolutions, urls
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination
- Example:
```python
await get_ip_relationship(
    ip="8.8.8.8",
    relationship="communicating_files",
    limit=20
)
```

### 4. Domain Relationship Tool
- Name: `get_domain_relationship`
- Description: Query a specific relationship type for a domain with pagination support
- Parameters:
  * `domain` (required): Domain name to analyze
  * `relationship` (required): Type of relationship to query
    - Available relationships: caa_records, cname_records, comments, communicating_files, downloaded_files, historical_ssl_certificates, historical_whois, immediate_parent, mx_records, ns_records, parent, referrer_files, related_comments, related_references, related_threat_actors, resolutions, soa_records, siblings, subdomains, urls, user_votes
  * `limit` (optional, default: 10): Maximum number of related objects to retrieve (1-40)
  * `cursor` (optional): Continuation cursor for pagination
- Example:
```python
await get_domain_relationship(
    domain="example.com",
    relationship="historical_ssl_certificates",
    limit=20
)
```

### 5. Advanced Search Tool
- Name: `advanced_corpus_search`
- Description: Perform advanced searches across the VirusTotal dataset using VT Intelligence query syntax
- Parameters:
  * `query` (required): The VT Intelligence search query string
  * `limit` (optional, default: 20): Maximum number of results to return per page
  * `cursor` (optional): Continuation cursor for pagination
  * `descriptors_only` (optional): If true, retrieves only object descriptors instead of full objects
- Example:
```python
await advanced_corpus_search(
    query="type:peexe size:100kb+ positives:5+",
    limit=20,
    cursor=None
)
```

## Requirements

- Python >= 3.11
- A valid [VirusTotal API Key](https://www.virustotal.com/gui/my-apikey)
- Required Python packages:
  * aiohttp >= 3.9.0
  * mcp[cli] >= 1.4.1
  * python-dotenv >= 1.0.0
  * typing-extensions >= 4.8.0

## Error Handling

The server includes comprehensive error handling for:
- Invalid API keys
- Rate limiting
- Network errors
- Invalid input parameters
- Invalid hash formats
- Invalid IP formats
- Invalid URL formats
- Invalid relationship types
- Pagination errors

## Development

To run in development mode:
```bash
python -m virustotal_mcp
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- VirusTotal for providing the API and threat intelligence platform
- The MCP project for the server framework
- Contributors and maintainers

## Support

For support, please:
1. Check the documentation
2. Search existing issues
3. Create a new issue if needed

## Security

- Never commit API keys or sensitive credentials
- Use environment variables for configuration
- Follow security best practices when handling threat intelligence data 