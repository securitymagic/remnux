# Hunt queries — adapt to your telemetry schema

The parameter patterns can surface related deployments and are **not proof of malware**. Prefer combinations of domain, full URI, signer verification, hash, and behavior.

## KQL (Microsoft Defender XDR / Advanced Hunting)

```kusto
DeviceNetworkEvents
| where Timestamp > ago(90d)
| where RemoteUrl has_any ("applicensingstudio.com", "setuppdfsoft.com", "cookingsuiteinstaller.com", "reciperoverapp.com", "nomadiccooknow.com", "nomadiccookapp.com", "mypdfsoftware.com", "webpdfinstallerstudio.com", "appsetupstore.com", "peregrinecooksoft.com")
| project Timestamp, DeviceName, RemoteUrl, InitiatingProcessFileName, InitiatingProcessSHA256, ActionType
```

Note: `RemoteUrl` may record the FQDN without the HTTP path/query. Use web proxy logs for detecting `init=prep`/`init=fin`.

## Splunk SPL (proxy logs with URL field)

```spl
index=proxy ("init=prep" OR "init=fin")
| eval full_url=coalesce(url, uri, cs_uri)
| where like(full_url, "%init=prep%") OR like(full_url, "%init=fin%")
| rex field=full_url "(?i)(?:[?&])(?<stage>init=(?:prep|fin))(?:&|$)"
| stats count values(full_url) as example_urls values(stage) as stages by src_ip dest_host
```

## Generic SQL / SIEM predicate on decoded HTTP query string

```sql
WHERE (
    LOWER(url) LIKE '%init=prep%'
    OR LOWER(url) LIKE '%init=fin%'
  )
  AND (
    LOWER(url) LIKE '%&chan=%&lang=%&arch=%&build=%'
    OR LOWER(url) LIKE '%appid=%&revid=%'
    OR LOWER(url) LIKE '%ver=%&apiid=%'
  )
```

*SQL wildcard queries are conceptual; actual order/query parsing differs by product. They trade sensitivity for higher precision.*

## Endpoint triage

- Hash-match the submitted CSV (`SHA256`); verify files before actions.
- For suspicious installers, correlate reported signing identity with actual Authenticode trust, process ancestry, and outbound full URLs.
- Look for **network response followed by executable allocation/memory mapping and process/module execution**; generic memory APIs are common and need contextual triage.
- Group by host and 5–15 minute window to connect a prep request, possible fin response, new process, and subsequent downloads.
