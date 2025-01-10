import { Hono } from 'hono';
import { html } from 'hono/html';
import { jwt, decode, sign, verify } from 'hono/jwt';
import { getCookie, getSignedCookie, setCookie, setSignedCookie, deleteCookie, } from 'hono/cookie'
import bcrypt from 'bcryptjs';

const app = new Hono();

const layout = (content) => html`
<!DOCTYPE html>
  <html>
    <head>
      <title>DMARC Analytics Dashboard</title>
      <link rel="stylesheet" type="text/css" href="https://utfs.io/f/tU8vX4DFrVItrPVq01O3zjgmsyVWNbB0HhXDRkYxZeiOq4nI">
    </head>
    <body>
      <nav class="navbar">
        <div class="nav">
          <a href="/dashboard/">Dashboard</a>
          <a href="/dashboard/auth-rates">Auth Rates</a>
          <a href="/dashboard/top-senders">Top Senders</a>
          <a href="/dashboard/geo-location">Geo Location</a>
          <a href="/dashboard/compliance-trends">Compliance</a>
          <a href="/dashboard/detailed-reports">Reports</a>
          <a href="/dashboard/failure-analysis">Failures</a>
          <a href="/dashboard/domain-summary">Domains</a>
          <a href="/logout">Logout</a>
        </div>
      </nav>
      <main class="container">
        ${content}
      </main>
    </body>
  </html>
`;

// Types
const DispositionType = {
  none: 1,
  quarantine: 2,
  reject: 3
};

const DMARCResultType = {
  pass: 1,
  fail: 2
};

// Auth middleware
app.use('/dashboard/*', async (c, next) => {
  const tokenToVerify = getCookie(c, 'jwt')
  
  if (!tokenToVerify) {
    console.log(('Authentication required', 401))
    return c.redirect('/logout');
  }

  try {
    const decodedPayload = await verify(tokenToVerify, c.env.JWT_SECRET_KEY)
    
    if (!decodedPayload.customerId) {
      console.log(('Invalid token: missing customer ID', 400))
      return c.redirect('/logout');
    }
    
    c.set('customerId', decodedPayload.customerId)
    
    await next()
  } catch (error) {
    console.error('Token verification failed:', error)
    return c.redirect('/logout');
  }
})

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

app.get('/dashboard/', async (c) => {
  const customerId = c.get('customerId');
  const stats = await fetchData(c.env, `
    SELECT 
      COUNT(*) as total_reports,
      COUNT(DISTINCT source_ip) as unique_ips,
      COUNT(DISTINCT header_from) as unique_domains,
      COALESCE(SUM(CASE WHEN dkim_result = 1 AND spf_result = 1 THEN 1 ELSE 0 END) * 100.0 / NULLIF(COUNT(*), 0), 0) as success_rate
    FROM dmarc_reports
    WHERE customer_id = ?1
  `, [customerId]);

  const statsObj = stats?.[0] ?? { total_reports: 0, unique_ips: 0, unique_domains: 0, success_rate: 0 };

  const content = html`
    <h1>DMARC Analytics Overview for ${customerId}</h1>
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
  
  return c.html(layout(content));
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
  
  return c.html(layout(content));
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
  
  return c.html(layout(content));
});

// Endpoint: Geographic distribution of email sources
app.get('/dashboard/geo-location', async (c) => {
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
  
  return c.html(layout(content));
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
  
  return c.html(layout(content));
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
  
  return c.html(layout(content));
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
  
  return c.html(layout(content));
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
  
  const formatDisposition = (disposition) => {
    switch (disposition) {
      case DispositionType.reject:
        return '✓ Reject';
      case DispositionType.quarantine:
        return '⚠️ Quarantine';
      case DispositionType.none:
        return '✗ None';
      default:
        return '? Unknown';
    }
  };

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
          <td>${row.dkim_result === DMARCResultType.pass ? '✓' : '✗'}</td>
          <td>${row.spf_result === DMARCResultType.pass ? '✓' : '✗'}</td>
          <td>${formatDisposition(row.disposition)}</td>
          <td>${row.policy_override_type || 'None'}</td>
          <td>${row.error || 'None'}</td>
        </tr>
      `)}
    </table>
  `;
  
  return c.html(layout(content));
});

app.get('/dashboard/config', async (c) => {
  const customerId = c.get('customerId');

  const content = html`
    <h1>Strict Config:</h1>
    <p>v=DMARC1; p=reject; rua=mailto:${customerId}@huzzand.buzz; pct=100; adkim=s; aspf=s;</p>
    <br>
    <h1>Less Strict Config:</h1>
    <p>v=DMARC1; p=quarantine; rua=mailto:${customerId}@huzzand.buzz; pct=20; adkim=r; aspf=r;</p>
  `;
  
  return c.html(layout(content));
});

app.get('/login', (c) => {
  const form = html`
  <!DOCTYPE html>
  <html>
    <head>
      <title>DMARC Analytics Dashboard</title>
      <link rel="stylesheet" type="text/css" href="https://utfs.io/f/tU8vX4DFrVItrPVq01O3zjgmsyVWNbB0HhXDRkYxZeiOq4nI">
    </head>
    <body>
      <main class="container">
        <form method="POST" action="/login" class="login-form">
          <label>
            Customer ID:
            <input name="customerId" type="text" placeholder="Enter your customer ID" />
          </label>
          <label>
            Password:
            <input type="password" name="password" placeholder="Enter your password" />
          </label>
          <button type="submit">Login</button>
          <a href="/register">Want to register?</a>
        </form>
      </main>
    </body>
  </html>
  `;
  return c.html(form);
});

app.get('/register', (c) => {
  const form = html`
  <!DOCTYPE html>
  <html>
    <head>
      <title>DMARC Analytics Dashboard</title>
      <link rel="stylesheet" type="text/css" href="https://utfs.io/f/tU8vX4DFrVItrPVq01O3zjgmsyVWNbB0HhXDRkYxZeiOq4nI">
    </head>
    <body>
      <main class="container">
        <form method="POST" action="/register" class="login-form">
          <label>
            Customer ID:
            <input name="customerId" type="text" placeholder="Enter prefered customer ID" />
          </label>
          <label>
            Password:
            <input type="password" name="password" placeholder="Enter your password" />
          </label>
          <button type="submit">Register</button>
          <a href="/login">Want to login?</a>
        </form>
      </main>
    </body>
  </html>
  `;
  return c.html(form);
});

app.post('/register', async (c) => {
  const { customerId, password } = await c.req.parseBody();
  const alreadyExists = await c.env.HUZZANDBUZZ_ACCOUNTS.get(customerId)

  if (alreadyExists) {
    return c.text('Customer ID already exist', 409)
  }

  if (password) {
    const saltRounds = 10
    const hashedPassword = bcrypt.hashSync(password, saltRounds);
    await c.env.HUZZANDBUZZ_ACCOUNTS.put(customerId, hashedPassword)

    const token = await sign({ customerId, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, }, c.env.JWT_SECRET_KEY);

    setCookie(c, 'jwt', token, {
        httpOnly: true,
        maxAge: 24 * 60 * 60,
    });
    return c.redirect(`/dashboard/config`);
  }
  return c.text('Invalid credentials', 401);
});

app.post('/login', async (c) => {
  const { customerId, password } = await c.req.parseBody();
  const accountPassword = await c.env.HUZZANDBUZZ_ACCOUNTS.get(customerId)

  const isMatch = bcrypt.compareSync(password, accountPassword);

  if (isMatch) {
    const token = await sign({ customerId, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, }, c.env.JWT_SECRET_KEY);

    setCookie(c, 'jwt', token, { httpOnly: true });
    return c.redirect(`/dashboard/`);
  }
  return c.text('Invalid credentials', 401);
});

app.get('/logout', (c) => {
  setCookie(c, 'jwt', '', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: '/',
    expires: new Date(0)
  });
  
  return c.redirect('/login');
});

app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DMARC Management - Huzz And Buzz</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <style>
        .gradient-bg {
            background: linear-gradient(135deg, #1a365d 0%, #2563eb 100%);
        }
    </style>
</head>
<body class="font-sans">
    <!-- Header -->
    <header class="gradient-bg text-white">
        <nav class="container mx-auto px-6 py-4 flex justify-between items-center">
            <div class="text-xl font-bold">Huzz And Buzz</div>
            <div class="space-x-6">
                <a href="#features" class="hover:text-blue-200">Features</a>
                <a href="#how-it-works" class="hover:text-blue-200">How It Works</a>
                <a href="/dashboard/" class="hover:text-blue-200">Dashboard</a>
                <a href="/login" class="bg-white text-blue-600 px-4 py-2 rounded-lg hover:bg-blue-50">Login</a>
            </div>
        </nav>

        <!-- Hero Section -->
        <div class="container mx-auto px-6 py-20">
            <div class="max-w-3xl">
                <h1 class="text-5xl font-bold mb-6">Secure Your Email Domain with Powerful DMARC Management</h1>
                <p class="text-xl mb-8">Protect your brand and improve email deliverability with our comprehensive DMARC analysis and reporting solution.</p>
                <a href="/register" class="bg-white text-blue-600 px-8 py-4 rounded-lg text-lg font-semibold hover:bg-blue-50">Get Started Free</a>
            </div>
        </div>
    </header>

    <!-- Features Section -->
    <section id="features" class="py-20">
        <div class="container mx-auto px-6">
            <h2 class="text-3xl font-bold text-center mb-16">Comprehensive Email Security Made Simple</h2>
            <div class="grid grid-cols-1 md:grid-cols-3 gap-12">
                <div class="text-center">
                    <div class="bg-blue-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-6">
                        <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <h3 class="text-xl font-semibold mb-4">Real-time Monitoring</h3>
                    <p class="text-gray-600">Track email authentication attempts and identify potential security threats instantly.</p>
                </div>
                <div class="text-center">
                    <div class="bg-blue-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-6">
                        <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                        </svg>
                    </div>
                    <h3 class="text-xl font-semibold mb-4">Detailed Analytics</h3>
                    <p class="text-gray-600">Get comprehensive insights into your email authentication performance and security metrics.</p>
                </div>
                <div class="text-center">
                    <div class="bg-blue-100 rounded-full w-16 h-16 flex items-center justify-center mx-auto mb-6">
                        <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064" />
                        </svg>
                    </div>
                    <h3 class="text-xl font-semibold mb-4">Geographic Insights</h3>
                    <p class="text-gray-600">Visualize the global distribution of your email traffic and identify suspicious patterns.</p>
                </div>
            </div>
        </div>
    </section>

    <!-- How It Works Section -->
    <section id="how-it-works" class="py-20 bg-gray-50">
        <div class="container mx-auto px-6">
            <h2 class="text-3xl font-bold text-center mb-16">Get Started in Minutes</h2>
            <div class="max-w-3xl mx-auto space-y-12">
                <div class="flex items-start">
                    <div class="bg-blue-600 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 mt-1">1</div>
                    <div class="ml-4">
                        <h3 class="text-xl font-semibold mb-2">Access Your Dedicated Email</h3>
                        <p class="text-gray-600">Receive a unique email address linked to your account for collecting DMARC reports.</p>
                    </div>
                </div>
                <div class="flex items-start">
                    <div class="bg-blue-600 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 mt-1">2</div>
                    <div class="ml-4">
                        <h3 class="text-xl font-semibold mb-2">Add DNS Record</h3>
                        <p class="text-gray-600">Add a simple TXT record to your DNS settings:</p>
                        <code class="bg-gray-100 px-4 py-2 rounded-lg block mt-2">
                            Name: _dmarc<br>
                            Value: v=DMARC1; p=quarantine; rua=mailto:customerid@huzzand.buzz;
                        </code>
                    </div>
                </div>
                <div class="flex items-start">
                    <div class="bg-blue-600 text-white rounded-full w-8 h-8 flex items-center justify-center flex-shrink-0 mt-1">3</div>
                    <div class="ml-4">
                        <h3 class="text-xl font-semibold mb-2">Access Your Dashboard</h3>
                        <p class="text-gray-600">Log in with your customer ID to view comprehensive reports and analysis.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Dashboard Preview Section -->
    <section id="dashboard" class="py-20">
        <div class="container mx-auto px-6">
            <h2 class="text-3xl font-bold text-center mb-16">Powerful Dashboard Analytics</h2>
            <div class="bg-white rounded-xl shadow-2xl overflow-hidden">
                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8 p-8">
                    <div>
                        <h3 class="font-semibold mb-2">Authentication Overview</h3>
                        <p class="text-gray-600">Track all email authentication attempts with detailed success and failure rates.</p>
                    </div>
                    <div>
                        <h3 class="font-semibold mb-2">IP Intelligence</h3>
                        <p class="text-gray-600">Monitor all IP addresses sending emails on behalf of your domain.</p>
                    </div>
                    <div>
                        <h3 class="font-semibold mb-2">Geographic Analysis</h3>
                        <p class="text-gray-600">View global distribution of email origins with interactive maps.</p>
                    </div>
                    <div>
                        <h3 class="font-semibold mb-2">Authentication Rates</h3>
                        <p class="text-gray-600">Monitor the proportion of genuine emails being sent from your domain.</p>
                    </div>
                    <div>
                        <h3 class="font-semibold mb-2">Detailed Reports</h3>
                        <p class="text-gray-600">Access comprehensive error rate analysis and troubleshooting insights.</p>
                    </div>
                    <div>
                        <h3 class="font-semibold mb-2">Domain Management</h3>
                        <p class="text-gray-600">Track and manage all associated domains from a single interface.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- CTA Section -->
    <section class="gradient-bg text-white py-20">
        <div class="container mx-auto px-6 text-center">
            <h2 class="text-3xl font-bold mb-8">Ready to Secure Your Email Domain?</h2>
            <p class="text-xl mb-8 max-w-2xl mx-auto">Join thousands of organizations using Huzz And Buzz for comprehensive DMARC management and email security.</p>
            <a href="/register" class="bg-white text-blue-600 px-8 py-4 rounded-lg text-lg font-semibold hover:bg-blue-50">Start Free Trial</a>
        </div>
    </section>

    <!-- Footer -->
    <footer class="bg-gray-900 text-gray-300 py-12">
        <div class="container mx-auto px-6">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-12">
                <div>
                    <h3 class="text-white font-bold mb-4">Huzz And Buzz</h3>
                    <p class="text-sm">Securing email communications through advanced DMARC management and analysis.</p>
                </div>
                <div>
                    <h4 class="text-white font-semibold mb-4">Product</h4>
                    <ul class="space-y-2 text-sm">
                        <li><a href="#features" class="hover:text-white">Features</a></li>
                        <li><a href="#pricing" class="hover:text-white">Pricing</a></li>
                        <li><a href="/dashboard/" class="hover:text-white">Dashboard</a></li>
                    </ul>
                </div>
                <div>
                    <h4 class="text-white font-semibold mb-4">Resources</h4>
                    <ul class="space-y-2 text-sm">
                        <li><a href="#docs" class="hover:text-white">Documentation</a></li>
                        <li><a href="#blog" class="hover:text-white">Blog</a></li>
                        <li><a href="#support" class="hover:text-white">Support</a></li>
                    </ul>
                </div>
                <div>
                    <h4 class="text-white font-semibold mb-4">Company</h4>
                    <ul class="space-y-2 text-sm">
                        <li><a href="#about" class="hover:text-white">About Us</a></li>
                        <li><a href="#contact" class="hover:text-white">Contact</a></li>
                        <li><a href="#privacy" class="hover:text-white">Privacy Policy</a></li>
                        <li><a href="https://donotshow.me" class="hover:text-white">Temp Email</a></li>
                    </ul>
                </div>
            </div>
            <div class="border-t border-gray-800 mt-12 pt-8 text-sm text-center">
                <p>&copy; 2025 Huzz And Buzz. All rights reserved.</p>
            </div>
        </div>
    </footer>
</body>
</html>
`);
});

export default {
  fetch: app.fetch,
};
