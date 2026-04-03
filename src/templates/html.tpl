{{- if . }}
    <h2 class="image-title">{{- escapeXML ( index . 0 ).Target }}</h2>
    <table>
    {{- range . }}
      <tr class="group-header"><th colspan="__TOTAL_COLS__">{{ .Type | toString | escapeXML }}</th></tr>
      {{- if (eq (len .Vulnerabilities) 0) }}
      <tr><th colspan="__TOTAL_COLS__">No Vulnerabilities found</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Package</th>
        <th>Vulnerability ID</th>
        <th>Severity</th>
        <th>Installed Version</th>
        <th>Fixed Version</th>
{{/* LINKS_ONLY */}}
        <th>Links</th>
{{/* END_LINKS_ONLY */}}
      </tr>
        {{- range .Vulnerabilities }}
      <tr class="severity-{{ escapeXML .Vulnerability.Severity }}">
        <td class="pkg-name">{{ escapeXML .PkgName }}</td>
        <td>{{ escapeXML .VulnerabilityID }}</td>
        <td class="severity">{{ escapeXML .Vulnerability.Severity }}</td>
        <td class="pkg-version">{{ escapeXML .InstalledVersion }}</td>
        <td>{{ escapeXML .FixedVersion }}</td>
{{/* LINKS_ONLY */}}
        <td class="links" data-more-links="off">
          {{- range .Vulnerability.References }}
          <a href={{ escapeXML . | printf "%q" }}>{{ escapeXML . }}</a>
          {{- end }}
        </td>
{{/* END_LINKS_ONLY */}}
      </tr>
        {{- end }}
      {{- end }}
      {{- if (eq (len .Misconfigurations ) 0) }}
      <tr><th colspan="__TOTAL_COLS__">No Misconfigurations found</th></tr>
      {{- else }}
      <tr class="sub-header">
        <th>Type</th>
        <th>Misconf ID</th>
        <th>Check</th>
        <th>Severity</th>
        <th>Message</th>
      </tr>
        {{- range .Misconfigurations }}
      <tr class="severity-{{ escapeXML .Severity }}">
        <td class="misconf-type">{{ .Type | toString | escapeXML }}</td>
        <td>{{ escapeXML .ID }}</td>
        <td class="misconf-check">{{ escapeXML .Title }}</td>
        <td class="severity">{{ escapeXML .Severity }}</td>
        <td class="link" data-more-links="off" style="white-space:normal;">
          {{ escapeXML .Message }}
{{/* LINKS_ONLY */}}
          <br>
            <a href={{ escapeXML .PrimaryURL | printf "%q" }}>{{ escapeXML .PrimaryURL }}</a>
          </br>
{{/* END_LINKS_ONLY */}}
        </td>
      </tr>
        {{- end }}
      {{- end }}
    {{- end }}
    </table>
    {{- else }}
    <p>Scanner Returned Empty Report</p>
    {{- end }}
