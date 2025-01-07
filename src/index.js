import { Hono } from 'hono';
import { html } from 'hono/html';

const app = new Hono();

const layout = (customerId, content) => html`
  <!DOCTYPE html>
  <html>
    <head>
      <title>DMARC Analytics Dashboard</title>
      <link rel="stylesheet" type="text/css" href="https://utfs.io/f/tU8vX4DFrVItTibqvzxGWgkIHxCqj4wf6byiNc71MoKQdEle">
    </head>
    <body>
      <nav class="navbar">
        <div class="nav">
          <a href="/dashboard/?customer=${customerId}">Dashboard</a>
          <a href="/dashboard/auth-rates?customer=${customerId}">Auth Rates</a>
          <a href="/dashboard/top-senders?customer=${customerId}">Top Senders</a>
          <a href="/dashboard/geo-distribution?customer=${customerId}">Geo Distribution</a>
          <a href="/dashboard/compliance-trends?customer=${customerId}">Compliance</a>
          <a href="/dashboard/detailed-reports?customer=${customerId}">Reports</a>
          <a href="/dashboard/failure-analysis?customer=${customerId}">Failures</a>
          <a href="/dashboard/domain-summary?customer=${customerId}">Domains</a>
        </div>
      </nav>
      <main class="container">
        ${content}
      </main>
    </body>
  </html>
`;

// Auth middleware
app.use('/dashboard/*', async (c, next) => {
  const customerId = c.req.query('customer');
  if (!customerId) {
    return c.text('Missing customer parameter', 400);
  }
  
  const isValid = await c.env.DMARC_DOMAINS.get(customerId);
  if (!isValid) {
    return c.text('Invalid customer', 401);
  }
  
  c.set('customerId', customerId);
  await next();
});

// Helper function to fetch data from the database
async function fetchData(env, query, params) {
  try {
    let stmt = await env.DB.prepare(query);
    
    // If params is an array, use bind
    if (Array.isArray(params)) {
      stmt = await stmt.bind(...params);
    }
    
    const result = await stmt.all();
    return result.results || [];
  } catch (error) {
    console.error('Database error:', error);
    return [];
  }
}

// Add error handling middleware
app.onError((err, c) => {
  console.error('Application error:', err);
  return c.html(html`
    <h1>Error</h1>
    <p>An error occurred while processing your request.</p>
  `, 500);
});

app.get('/dashboard', async (c) => {
  const customerId = c.get('customerId');
  const stats = await fetchData(c.env, `
    SELECT 
      COUNT(*) as total_reports,
      COUNT(DISTINCT source_ip) as unique_ips,
      COUNT(DISTINCT header_from) as unique_domains,
      SUM(CASE WHEN dkim_result = 1 AND spf_result = 1 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as success_rate
    FROM dmarc_reports
    WHERE customer_id = ?1
  `, [customerId]);

  const statsObj = stats.length > 0 ? stats[0] : { total_reports: 0, unique_ips: 0, unique_domains: 0, success_rate: 0 };

  const content = html`
    <h1>DMARC Analytics Overview</h1>
    <div class="stats-grid">
      <div class="stat-card">
        <h3>Total Reports</h3>
        <div class="value">${statsObj.total_reports.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <h3>Unique IPs</h3>
        <div class="value">${statsObj.unique_ips.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <h3>Unique Domains</h3>
        <div class="value">${statsObj.unique_domains.toLocaleString()}</div>
      </div>
      <div class="stat-card">
        <h3>Success Rate</h3>
        <div class="value">${statsObj.success_rate.toFixed(1)}%</div>
      </div>
    </div>
  `;
  
  return c.html(layout(customerId, content));
});

// Endpoint: Authentication success/failure rates over time
app.get('/dashboard/auth-rates', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT date_range_begin, date_range_end, COUNT(*) as total, 
            SUM(CASE WHEN dkim_result = 1 AND spf_result = 1 THEN 1 ELSE 0 END) as success,
            SUM(CASE WHEN dkim_result = 0 OR spf_result = 0 THEN 1 ELSE 0 END) as failure
    FROM dmarc_reports
    WHERE customer_id = ?1
    GROUP BY date_range_begin, date_range_end
    ORDER BY date_range_begin
    LIMIT 30
  `, [customerId]);
  
  const content = html`
    <h1>Authentication Success/Failure Rates</h1>
    <table>
      <tr><th>Date Range</th><th>Total</th><th>Success</th><th>Failure</th></tr>
      ${data.map(row => html`
        <tr>
          <td>${new Date(row.date_range_begin * 1000).toLocaleDateString()} - ${new Date(row.date_range_end * 1000).toLocaleDateString()}</td>
          <td>${row.total.toLocaleString()}</td>
          <td class="success">${row.success.toLocaleString()}</td>
          <td class="error">${row.failure.toLocaleString()}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// Endpoint: Top sending IP addresses and their performance
app.get('/dashboard/top-senders', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT source_ip, COUNT(*) as total, 
           SUM(CASE WHEN dkim_result = 1 AND spf_result = 1 THEN 1 ELSE 0 END) as success,
           SUM(CASE WHEN dkim_result = 0 OR spf_result = 0 THEN 1 ELSE 0 END) as failure
    FROM dmarc_reports
    WHERE customer_id = ?1
    GROUP BY source_ip
    ORDER BY total DESC
    LIMIT 10
  `, [customerId]);
  
  const content = html`
    <h1>Top Sending IP Addresses and Their Performance</h1>
    <table>
      <tr><th>IP Address</th><th>Total</th><th>Success</th><th>Failure</th></tr>
      ${data.map(row => html`
        <tr>
          <td>${row.source_ip}</td>
          <td>${row.total}</td>
          <td>${row.success}</td>
          <td>${row.failure}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// Endpoint: Geographic distribution of email sources
app.get('/dashboard/geo-distribution', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT source_ip, COUNT(*) as total
    FROM dmarc_reports
    WHERE customer_id = ?1
    GROUP BY source_ip
  `, [customerId]);
  
  async function getLocationData(ip) {
    try {
      const response = await fetch(
        `http://ip-api.com/json/${ip}?fields=country`,
        { timeout: 5000 }
      );
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      
      const locationData = await response.json();
      return locationData.country;
    } catch (error) {
      console.error(`Error fetching location for IP ${ip}:`, error);
      return 'Unknown';
    }
  }
  
  const geoData = await Promise.all(
    data.map(async row => ({
      ip: row.source_ip,
      total: row.total,
      location: await getLocationData(row.source_ip)
    }))
  );
  
  const content = html`
    <h1>Geographic Distribution of Email Sources</h1>
    <table>
      <tr><th>IP Address</th><th>Total</th><th>Location</th></tr>
      ${geoData.map(row => html`
        <tr>
          <td>${row.ip}</td>
          <td>${row.total}</td>
          <td>${row.location}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// Endpoint: Compliance trends and policy effectiveness
app.get('/dashboard/compliance-trends', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT date_range_begin, date_range_end, COUNT(*) as total, 
           SUM(CASE WHEN disposition = 1 THEN 1 ELSE 0 END) as compliant,
           SUM(CASE WHEN disposition = 0 THEN 1 ELSE 0 END) as non_compliant
    FROM dmarc_reports
    WHERE customer_id = ?1
    GROUP BY date_range_begin, date_range_end
    ORDER BY date_range_begin
  `, [customerId]);
  
  const content = html`
    <h1>Compliance Trends and Policy Effectiveness</h1>
    <table>
      <tr><th>Date Range</th><th>Total</th><th>Compliant</th><th>Non-Compliant</th></tr>
      ${data.map(row => html`
        <tr>
          <td>${new Date(row.date_range_begin * 1000).toLocaleDateString()} - ${new Date(row.date_range_end * 1000).toLocaleDateString()}</td>
          <td>${row.total}</td>
          <td>${row.compliant}</td>
          <td>${row.non_compliant}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// New endpoint: Detailed failure analysis
app.get('/dashboard/failure-analysis', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT 
      header_from,
      source_ip,
      COUNT(*) as total_failures,
      SUM(CASE WHEN dkim_result = 2 THEN 1 ELSE 0 END) as dkim_failures,
      SUM(CASE WHEN spf_result = 2 THEN 1 ELSE 0 END) as spf_failures,
      policy_override_type,
      error,
      COUNT(*) * 1.0 / SUM(count) as failure_rate
    FROM dmarc_reports
    WHERE customer_id = ?1 
    AND (dkim_result = 2 OR spf_result = 2)
    GROUP BY header_from, source_ip, policy_override_type, error
    ORDER BY total_failures DESC
  `, [customerId]);
  
  const content = html`
    <h1>Failure Analysis</h1>
    <table>
      <tr>
        <th>Domain</th>
        <th>IP</th>
        <th>Total Failures</th>
        <th>DKIM Failures</th>
        <th>SPF Failures</th>
        <th>Failure Rate</th>
        <th>Override Type</th>
        <th>Error</th>
      </tr>
      ${data.map(row => html`
        <tr>
          <td>${row.header_from}</td>
          <td>${row.source_ip}</td>
          <td>${row.total_failures}</td>
          <td>${row.dkim_failures}</td>
          <td>${row.spf_failures}</td>
          <td>${(row.failure_rate * 100).toFixed(1)}%</td>
          <td>${row.policy_override_type || 'None'}</td>
          <td>${row.error || 'None'}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// New endpoint: Domain summary
app.get('/dashboard/domain-summary', async (c) => {
  const customerId = c.get('customerId');
  const data = await fetchData(c.env, `
    SELECT 
      ds.domain,
      ds.report_count,
      ds.first_seen,
      ds.last_seen,
      COUNT(DISTINCT dr.source_ip) as unique_ips,
      SUM(CASE WHEN dr.dkim_result = 1 AND dr.spf_result = 1 THEN 1 ELSE 0 END) as passed,
      COUNT(*) as total
    FROM domain_stats ds
    LEFT JOIN dmarc_reports dr ON ds.domain = dr.header_from
    WHERE ds.customer_id = ?1
    GROUP BY ds.domain
    ORDER BY ds.report_count DESC
  `, [customerId]);
  
  const content = html`
    <h1>Domain Summary</h1>
    <table>
      <tr>
        <th>Domain</th>
        <th>Report Count</th>
        <th>First Seen</th>
        <th>Last Seen</th>
        <th>Unique IPs</th>
        <th>Pass Rate</th>
      </tr>
      ${data.map(row => html`
        <tr>
          <td>${row.domain}</td>
          <td>${row.report_count}</td>
          <td>${new Date(row.first_seen).toLocaleDateString()}</td>
          <td>${new Date(row.last_seen).toLocaleDateString()}</td>
          <td>${row.unique_ips}</td>
          <td>${((row.passed / row.total) * 100).toFixed(2)}%</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

// New endpoint: Detailed reports with filtering
app.get('/dashboard/detailed-reports', async (c) => {
  const customerId = c.get('customerId');
  const startDate = c.req.query('start') || '';
  const endDate = c.req.query('end') || '';
  const domain = c.req.query('domain') || '';
  
  let query = `
    SELECT 
      date_range_begin,
      date_range_end,
      header_from,
      source_ip,
      dkim_result,
      spf_result,
      disposition,
      policy_override_type,
      error
    FROM dmarc_reports
    WHERE customer_id = ?1
  `;
  
  const params = [customerId];
  if (startDate) {
    query += ' AND date_range_begin >= ?2';
    params.push(Math.floor(new Date(startDate).getTime() / 1000));
  }
  if (endDate) {
    query += ' AND date_range_end <= ?3';
    params.push(Math.floor(new Date(endDate).getTime() / 1000));
  }
  if (domain) {
    query += ' AND header_from LIKE ?4';
    params.push(`%${domain}%`);
  }
  
  query += ' ORDER BY date_range_begin DESC LIMIT 1000';
  
  const data = await fetchData(c.env, query, params);
  
  const content = html`
    <h1>Detailed Reports</h1>
    <form class="filter-form">
      <input type="hidden" name="customer" value="${customerId}">
      <input type="date" name="start" value="${startDate}">
      <input type="date" name="end" value="${endDate}">
      <input type="text" name="domain" placeholder="Filter by domain" value="${domain}">
      <button type="submit">Filter</button>
    </form>
    <table>
      <tr>
        <th>Date</th>
        <th>Domain</th>
        <th>IP</th>
        <th>DKIM</th>
        <th>SPF</th>
        <th>Disposition</th>
        <th>Override</th>
        <th>Error</th>
      </tr>
      ${data.map(row => html`
        <tr>
          <td>${new Date(row.date_range_begin * 1000).toLocaleDateString()} - ${new Date(row.date_range_end * 1000).toLocaleDateString()}</td>
          <td>${row.header_from}</td>
          <td>${row.source_ip}</td>
          <td>${row.dkim_result ? '✓' : '✗'}</td>
          <td>${row.spf_result ? '✓' : '✗'}</td>
          <td>${row.disposition}</td>
          <td>${row.policy_override_type || 'None'}</td>
          <td>${row.error || 'None'}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(customerId, content));
});

export default {
  fetch: app.fetch,
};
