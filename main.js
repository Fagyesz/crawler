// Add Web Streams API polyfill for ReadableStream
globalThis.ReadableStream = require('stream/web').ReadableStream;

const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const axios = require('axios');
const cheerio = require('cheerio');
const url = require('url');
const FormData = require('form-data');
const querystring = require('querystring');
const fs = require('fs');
const https = require('https');
const { promisify } = require('util');

// Hide console window in production
if (process.env.NODE_ENV === 'production') {
  // This only affects Windows builds
  process.env.ELECTRON_NO_ATTACH_CONSOLE = true;
}

// Keep a global reference of the window object to prevent garbage collection
let mainWindow;
// Store cookies and session data
let cookieJar = {};
// Create an axios instance that handles cookies
const axiosInstance = axios.create({
  withCredentials: true,
  // Increase timeout for slow APIs
  timeout: 30000,
  // Configure HTTPS agent with relaxed SSL verification for testing
  httpsAgent: new https.Agent({
    rejectUnauthorized: false
  })
});

// Rate limiting configuration
const rateLimiter = {
  requests: {},
  maxRequestsPerMinute: 30,
  timeWindow: 60 * 1000, // 1 minute
  
  canMakeRequest(domain) {
    const now = Date.now();
    
    // Initialize domain if not exists
    if (!this.requests[domain]) {
      this.requests[domain] = [];
    }
    
    // Filter out old requests
    this.requests[domain] = this.requests[domain].filter(
      timestamp => now - timestamp < this.timeWindow
    );
    
    // Check if under limit
    if (this.requests[domain].length < this.maxRequestsPerMinute) {
      this.requests[domain].push(now);
      return true;
    }
    
    return false;
  },
  
  async waitForRateLimit(domain) {
    if (this.canMakeRequest(domain)) {
      return;
    }
    
    // Wait until we can make a request
    const waitTime = this.timeWindow - (Date.now() - this.requests[domain][0]);
    await new Promise(resolve => setTimeout(resolve, waitTime + 100));
    return this.waitForRateLimit(domain);
  }
};

function createWindow() {
  // Create the browser window with Windows 11 styling
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      nodeIntegration: true,
      contextIsolation: false,
      enableRemoteModule: true
    },
    frame: true,
    transparent: false,
    roundedCorners: true,
    backgroundColor: '#ffffff',
    titleBarStyle: 'default',
    titleBarOverlay: {
      color: '#f3f3f3',
      symbolColor: '#000000'
    }
  });

  // Load the index.html file
  mainWindow.loadFile(path.join(__dirname, 'index.html'));

  // Open DevTools in development mode
  if (process.argv.includes('--dev')) {
    mainWindow.webContents.openDevTools();
  }

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Create window when Electron is ready
app.whenReady().then(createWindow);

// Quit when all windows are closed
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  }
});

// First, we need to get the login page to identify the form
async function getLoginForm(loginUrl) {
  try {
    const domain = new URL(loginUrl).hostname;
    await rateLimiter.waitForRateLimit(domain);
    
    const response = await axios.get(loginUrl, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9'
      }
    });
    
    // Parse the HTML to find the form
    const $ = cheerio.load(response.data);
    const form = $('form').first();
    const formAction = form.attr('action') || loginUrl;
    const formMethod = (form.attr('method') || 'post').toLowerCase();
    
    // Convert relative URL to absolute
    const absoluteFormAction = new URL(formAction, loginUrl).href;
    
    // Get all hidden fields in the form
    const hiddenFields = {};
    form.find('input[type="hidden"]').each((i, el) => {
      const name = $(el).attr('name');
      const value = $(el).attr('value') || '';
      if (name) {
        hiddenFields[name] = value;
      }
    });
    
    // Get CSRF token if it exists
    let csrfToken = '';
    // Common CSRF token field names
    const csrfFields = ['csrf_token', '_csrf', '_token', 'csrf', 'token', 'authenticity_token', 'csrfmiddlewaretoken'];
    for (const field of csrfFields) {
      const tokenField = form.find(`input[name="${field}"]`);
      if (tokenField.length > 0) {
        csrfToken = tokenField.attr('value') || '';
        break;
      }
    }
    
    // Sometimes CSRF is in a meta tag
    if (!csrfToken) {
      const metaCsrf = $('meta[name="csrf-token"]');
      if (metaCsrf.length > 0) {
        csrfToken = metaCsrf.attr('content') || '';
      }
    }
    
    // Store cookies from the response
    if (response.headers['set-cookie']) {
      const cookies = response.headers['set-cookie'];
      
      if (!cookieJar[domain]) {
        cookieJar[domain] = [];
      }
      
      cookieJar[domain] = cookies;
    }
    
    return {
      action: absoluteFormAction,
      method: formMethod,
      hiddenFields,
      csrfToken
    };
  } catch (error) {
    console.error('Error getting login form:', error);
    throw new Error('Failed to get login form. Please check the URL and try again.');
  }
}

// Handle login requests from the renderer
ipcMain.on('login', async (event, loginData) => {
  try {
    const { loginUrl, username, password, usernameField, passwordField } = loginData;
    
    console.log(`Attempting login to: ${loginUrl}`);
    
    // Get login form details first
    const formDetails = await getLoginForm(loginUrl);
    
    // Prepare the headers
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Referer': loginUrl,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
      'Accept-Language': 'en-US,en;q=0.9'
    };
    
    // Add cookies if available
    const domain = new URL(loginUrl).hostname;
    if (cookieJar[domain]) {
      headers['Cookie'] = cookieJar[domain].join('; ');
    }
    
    // Prepare form data with hidden fields included
    const formData = {
      ...formDetails.hiddenFields,
      [usernameField]: username,
      [passwordField]: password
    };
    
    // If CSRF token found, include it
    if (formDetails.csrfToken) {
      formData._csrf = formDetails.csrfToken;
    }
    
    let response;
    
    await rateLimiter.waitForRateLimit(domain);
    
    // Submit the form based on the method (GET or POST)
    if (formDetails.method === 'get') {
      response = await axios.get(formDetails.action, {
        params: formData,
        headers,
        maxRedirects: 5,
        withCredentials: true
      });
    } else {
      // Use proper content type for form submission
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      
      // Convert form data to URL encoded string
      const formBody = querystring.stringify(formData);
      
      response = await axios.post(formDetails.action, formBody, {
        headers,
        maxRedirects: 5,
        withCredentials: true
      });
    }
    
    // Store cookies from the response
    if (response.headers['set-cookie']) {
      if (!cookieJar[domain]) {
        cookieJar[domain] = [];
      }
      
      cookieJar[domain] = response.headers['set-cookie'];
      console.log(`Cookies stored for domain: ${domain}`);
    }
    
    // Check login result
    const $ = cheerio.load(response.data);
    const pageText = $.text().toLowerCase();
    const pageUrl = response.request.res.responseUrl || loginUrl;
    
    // Common indicators of failed login
    const failureIndicators = [
      'incorrect password',
      'login failed',
      'invalid username',
      'invalid credentials',
      'wrong password',
      'user not found',
      'authentication failed',
      'login incorrect',
      'username or password is incorrect'
    ];
    
    // Check if any failure indicators are present
    const isLoginFailed = failureIndicators.some(indicator => pageText.includes(indicator));
    
    // Check if we got redirected back to login page
    const isRedirectedToLogin = pageUrl.includes('login') || pageUrl.includes('signin');
    
    if (isLoginFailed || isRedirectedToLogin) {
      throw new Error('Login failed: Invalid credentials or login form not recognized');
    }
    
    event.reply('login-result', { 
      success: true, 
      message: 'Login successful',
      cookies: cookieJar[domain] || []
    });
    
  } catch (error) {
    console.error('Error during login:', error);
    event.reply('login-result', { 
      success: false, 
      error: error.message || 'Login failed'
    });
  }
});

// Handle website crawling requests from the renderer
ipcMain.on('crawl-website', async (event, request) => {
  try {
    const { targetUrl, useAuth } = request;
    
    console.log(`Crawling: ${targetUrl}, Auth: ${useAuth}`);
    
    // Get the domain from URL
    const domain = new URL(targetUrl).hostname;
    
    // Check rate limiting
    await rateLimiter.waitForRateLimit(domain);
    
    // Prepare headers
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    };
    
    // Add cookies if using authentication
    if (useAuth && cookieJar[domain]) {
      headers['Cookie'] = cookieJar[domain].join('; ');
    }
    
    // Fetch the page
    const response = await axios.get(targetUrl, { 
      headers,
      timeout: 30000, // 30 second timeout
      validateStatus: status => status < 500, // Accept 4xx responses
      responseType: 'arraybuffer'  // Use arraybuffer for binary responses
    }).catch(error => {
      if (error.response) {
        return error.response; // Return the error response for analysis
      }
      throw error; // Re-throw if it's a network error
    });
    
    // Check if response is JSON (API)
    const contentType = response.headers['content-type'] || '';
    const isJson = contentType.includes('json') || contentType.includes('application/json');
    
    let apiData = null;
    let apis = [];
    let links = [];
    
    if (isJson) {
      // This is a direct API endpoint - parse the JSON data
      try {
        const responseText = response.data.toString('utf-8');
        apiData = JSON.parse(responseText);
        
        // Add the current URL as an API endpoint
        apis.push({
          url: targetUrl,
          method: 'GET',
          source: 'Direct API call',
          type: 'json-api',
          responsePreview: JSON.stringify(apiData).substring(0, 200) + '...',
          contentType: contentType,
          dataSize: JSON.stringify(apiData).length
        });
        
        // Return the JSON data immediately
        event.reply('crawl-result', {
          success: true,
          data: {
            url: targetUrl,
            isAuthenticated: useAuth,
            status: response.status,
            statusText: response.statusText,
            apis: apis,
            links: [],
            isApi: true,
            contentType: contentType,
            apiData: apiData,
            headers: Object.entries(response.headers).map(([key, value]) => ({ key, value }))
          }
        });
        return;
      } catch (error) {
        console.error('Error parsing JSON:', error);
        // If JSON parsing fails, continue with normal HTML processing
      }
    }
    
    // Parse the HTML if not JSON or JSON parsing failed
    if ((!isJson || !apiData) && response.status < 400) {
      const htmlContent = response.data.toString('utf-8');
      const $ = cheerio.load(htmlContent);
      
      // Find API endpoints
      const foundApis = findApiEndpoints($, targetUrl, htmlContent);
      apis = [...apis, ...foundApis];
      
      // Extract links
      $('a').each((i, el) => {
        let href = $(el).attr('href');
        if (!href) return;
        
        // Make relative URLs absolute
        if (href.startsWith('/')) {
          href = new URL(href, targetUrl).href;
        } else if (!href.startsWith('http')) {
          // Handle relative URLs without leading slash
          try {
            href = new URL(href, targetUrl).href;
          } catch (e) {
            // Skip invalid URLs
            return;
          }
        }
        
        // Skip mail links and anchors
        if (href.startsWith('mailto:') || href.startsWith('#') || href.startsWith('javascript:')) {
          return;
        }
        
        // Check if URL is from the same domain
        const linkDomain = isValidUrl(href) ? new URL(href).hostname : '';
        const sameDomain = linkDomain === domain;
        
        // Get link text
        let linkText = $(el).text().trim();
        linkText = linkText.length > 50 ? linkText.substring(0, 50) + '...' : linkText;
        
        // Determine link type for better classification
        let linkType = 'general';
        if (isApiLikeUrl(href)) {
          linkType = 'api';
        } else if (href.match(/\.(json|xml)$/i)) {
          linkType = 'data';
        } else if (href.match(/\/docs\/|\/documentation\/|\/guide\/|\/tutorial\/|\/help\//i)) {
          linkType = 'documentation';
        } else if (href.match(/\.(jpg|jpeg|png|gif|svg|webp)$/i)) {
          linkType = 'image';
        } else if (href.match(/\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt)$/i)) {
          linkType = 'document';
        } else if (href.includes('github.com') || href.includes('gitlab.com')) {
          linkType = 'repository';
        }
        
        // Check if this is a pagination link
        const isPagination = isPaginationLink(el, $);
        
        // Check if the link looks like it could be pointing to a JSON API
        const potentialJsonApi = href.includes('dummyjson.com') || 
                                href.includes('jsonplaceholder.typicode.com') || 
                                href.includes('randomuser.me/api') ||
                                href.includes('/api/') || 
                                href.match(/\.json$/i);
        
        links.push({
          url: href,
          text: linkText || href,
          sameDomain,
          isPagination,
          type: linkType,
          potentialJsonApi,
          hostname: linkDomain
        });
      });
      
      // Remove duplicates
      apis = removeDuplicateApis(apis);
      
      // Only keep unique URLs for links
      const uniqueLinks = [];
      const seenUrls = new Set();
      
      links.forEach(link => {
        if (!seenUrls.has(link.url)) {
          seenUrls.add(link.url);
          uniqueLinks.push(link);
        }
      });
      
      links = uniqueLinks;
    }
    
    // Send the result back to the renderer
    event.reply('crawl-result', {
      success: true,
      data: {
        url: targetUrl,
        isAuthenticated: useAuth,
        status: response.status,
        statusText: response.statusText,
        apis: apis,
        links: links,
        isApi: isJson && apiData !== null,
        contentType: contentType,
        apiData: apiData,
        headers: Object.entries(response.headers).map(([key, value]) => ({ key, value }))
      }
    });
  } catch (error) {
    console.error('Error crawling website:', error);
    // More descriptive error messages based on error type
    let errorMessage = error.message || 'An error occurred while crawling the website';
    
    if (error.code === 'ENOTFOUND') {
      errorMessage = `Domain not found: ${error.hostname}. Please check the URL and your internet connection.`;
    } else if (error.code === 'ECONNREFUSED') {
      errorMessage = `Connection refused at ${error.address}:${error.port}. The server may be down.`;
    } else if (error.code === 'ETIMEDOUT') {
      errorMessage = 'Connection timed out. The server took too long to respond.';
    } else if (error.response) {
      errorMessage = `Server returned ${error.response.status} ${error.response.statusText}`;
    }
    
    event.reply('crawl-result', {
      success: false,
      error: errorMessage
    });
  }
});

// Function to check if a link is a pagination link
function isPaginationLink(el, $) {
  const el$ = $(el);
  const text = el$.text().trim();
  const href = el$.attr('href') || '';
  
  // Common pagination patterns
  const paginationPatterns = [
    /^[0-9]+$/,  // Just a number
    /^page[=\/][0-9]+/i,  // page=X or page/X
    /[&\?]page=[0-9]+/,   // ?page=X or &page=X
    /[&\?]p=[0-9]+/,      // ?p=X or &p=X
    /^next$/i,           // "Next"
    /^prev(ious)?$/i,    // "Prev" or "Previous"
    /^«|»$/,             // « or »
    /^first$/i,          // "First"
    /^last$/i            // "Last"
  ];
  
  // Check if the text matches pagination patterns
  if (paginationPatterns.some(pattern => pattern.test(text))) {
    return true;
  }
  
  // Check if URL has pagination parameters
  if (href.match(/[\?&](page|p|offset|start|from|limit)=[0-9]+/)) {
    return true;
  }
  
  // Check for pagination classes
  const classAttr = el$.attr('class') || '';
  if (classAttr.match(/pagination|pager|page-link|page-item/i)) {
    return true;
  }
  
  // Check if the link is part of a pagination structure
  const parent = el$.parent();
  if (
    parent.hasClass('pagination') || 
    parent.hasClass('pager') || 
    parent.hasClass('page-item') || 
    parent.parent().hasClass('pagination')
  ) {
    return true;
  }
  
  return false;
}

// Handle API data fetch requests with advanced options
ipcMain.on('fetch-api-data', async (event, request) => {
  try {
    const { apiUrl, useAuth, method, headers: customHeaders } = request;
    
    console.log(`Fetching API data: ${apiUrl}, Method: ${method || 'GET'}`);
    
    // Get the domain from URL
    const domain = new URL(apiUrl).hostname;
    
    // Apply rate limiting
    await rateLimiter.waitForRateLimit(domain);
    
    // Prepare headers
    const headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
      'Accept': 'application/json, text/plain, */*',
      ...customHeaders
    };
    
    // Add cookies if using authentication
    if (useAuth && cookieJar[domain]) {
      headers['Cookie'] = cookieJar[domain].join('; ');
    }
    
    // Make the request
    const response = await axios({
      method: method || 'GET',
      url: apiUrl,
      headers,
      responseType: 'arraybuffer', // To handle binary responses
      timeout: 30000,
      validateStatus: status => true, // Accept all status codes for inspection
      maxRedirects: 5
    });
    
    // Get content type
    const contentType = response.headers['content-type'] || '';
    
    // Process response data based on content type
    let responseData;
    let dataType = 'unknown';
    
    try {
      if (contentType.includes('json')) {
        // JSON response
        responseData = JSON.parse(response.data.toString('utf-8'));
        dataType = 'json';
      } else if (contentType.includes('xml') || contentType.includes('text/html')) {
        // XML or HTML response
        responseData = response.data.toString('utf-8');
        dataType = contentType.includes('xml') ? 'xml' : 'html';
      } else if (contentType.includes('text/')) {
        // Other text response
        responseData = response.data.toString('utf-8');
        dataType = 'text';
      } else {
        // Binary response
        responseData = `Binary data (${contentType}) - ${response.data.length} bytes`;
        dataType = 'binary';
      }
    } catch (error) {
      console.error('Error processing response data:', error);
      responseData = 'Error processing response data: ' + error.message;
      dataType = 'error';
    }
    
    // Prepare headers for the reply
    const headersForReply = Object.entries(response.headers).map(([key, value]) => ({
      key,
      value: Array.isArray(value) ? value.join(', ') : value
    }));
    
    // Send response to renderer
    event.reply('api-data-result', {
      success: true,
      data: {
        url: apiUrl,
        method: method || 'GET',
        statusCode: response.status,
        statusText: response.statusText,
        contentType,
        data: responseData,
        dataType,
        headers: headersForReply
      }
    });
  } catch (error) {
    console.error('Error fetching API data:', error);
    
    // Generate a descriptive error message
    let errorMessage = 'Failed to fetch API data';
    
    if (error.code === 'ENOTFOUND') {
      errorMessage = `Domain not found: ${error.hostname}. Please check the URL.`;
    } else if (error.code === 'ECONNREFUSED') {
      errorMessage = `Connection refused. The server at ${error.address} may be down.`;
    } else if (error.code === 'ETIMEDOUT') {
      errorMessage = 'Connection timed out. The server took too long to respond.';
    } else if (error.response) {
      errorMessage = `Server returned ${error.response.status} ${error.response.statusText}`;
    } else {
      errorMessage = error.message || errorMessage;
    }
    
    event.reply('api-data-result', {
      success: false,
      error: errorMessage
    });
  }
});

// Check if a URL has an API-like structure
function isApiLikeUrl(url) {
  // Don't try to parse invalid URLs
  if (!url || typeof url !== 'string') return false;
  
  // URL path patterns that commonly indicate APIs
  const apiPatterns = [
    /\/api\//i,
    /\/graphql/i,
    /\/v\d+\//i,
    /\/rest\//i,
    /\/service/i,
    /\/endpoint/i,
    /\/data\//i,
    /\.json$/i,
    /\.xml$/i,
    /\/ajax\//i,
    /\/rpc/i,
    /\/soap\//i,
    /\/feed\//i,
    /\/query/i,
    /\/action/i,
    /\/method/i,
    /\/handler/i
  ];
  
  // Check against patterns
  return apiPatterns.some(pattern => pattern.test(url));
}

// Extract more types of APIs from JavaScript
function extractApisFromJavaScript(jsContent, baseUrl) {
  const apis = [];
  
  if (!jsContent) return apis;
  
  // Expanded patterns to detect API calls
  const patterns = [
    // Fetch API
    {
      regex: /fetch\(['"]([^'"]+)['"]\)/g,
      method: 'GET',
      type: 'fetch'
    },
    {
      regex: /fetch\(['"]([^'"]+)['"],\s*\{[^\}]*method:\s*['"]([^'"]+)['"]/g,
      method: 'dynamic',
      type: 'fetch'
    },
    // Axios
    {
      regex: /axios\s*\.\s*(get|post|put|delete|patch)\(['"]([^'"]+)['"]/g,
      method: 'dynamic',
      methodIndex: 1,
      urlIndex: 2,
      type: 'axios'
    },
    {
      regex: /axios\s*\(\s*\{\s*url:\s*['"]([^'"]+)['"],\s*method:\s*['"]([^'"]+)['"]/g,
      method: 'dynamic',
      urlIndex: 1,
      methodIndex: 2,
      type: 'axios'
    },
    // jQuery Ajax
    {
      regex: /\$\s*\.\s*(ajax|get|post|put|delete)\(['"]([^'"]+)['"]/g,
      method: 'dynamic',
      methodIndex: 1,
      urlIndex: 2,
      type: 'jquery'
    },
    {
      regex: /\$\s*\.\s*ajax\s*\(\s*\{\s*url:\s*['"]([^'"]+)['"],\s*type:\s*['"]([^'"]+)['"]/g,
      method: 'dynamic',
      urlIndex: 1,
      methodIndex: 2,
      type: 'jquery'
    },
    // XMLHttpRequest
    {
      regex: /\.open\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]/g,
      method: 'dynamic',
      methodIndex: 1,
      urlIndex: 2,
      type: 'xhr'
    },
    // Angular HttpClient
    {
      regex: /http\.(get|post|put|delete|patch)\(['"]([^'"]+)['"]/g,
      method: 'dynamic',
      methodIndex: 1,
      urlIndex: 2,
      type: 'angular'
    },
    // React useEffect with fetch
    {
      regex: /useEffect\(\s*\(\)\s*=>\s*\{\s*fetch\(['"]([^'"]+)['"]\)/g,
      method: 'GET',
      type: 'react-hook'
    },
    // URL patterns that look like APIs
    {
      regex: /["'](https?:\/\/[^"']*\/api\/[^"']*)['"]/g,
      method: 'GET',
      type: 'api-path'
    },
    {
      regex: /["'](https?:\/\/[^"']*\/v\d+\/[^"']*)['"]/g,
      method: 'GET',
      type: 'api-versioned'
    },
    {
      regex: /["'](https?:\/\/[^"']*\/graphql)['"]/g,
      method: 'POST',
      type: 'graphql'
    },
    {
      regex: /["'](https?:\/\/[^"']*\.(json|xml))['"]/g,
      method: 'GET',
      type: 'data-file'
    },
    // Environment variables that look like API URLs
    {
      regex: /API_URL\s*=\s*["'](https?:\/\/[^"']+)['"]/g,
      method: 'GET',
      type: 'env-var'
    },
    {
      regex: /API_ENDPOINT\s*=\s*["'](https?:\/\/[^"']+)['"]/g,
      method: 'GET',
      type: 'env-var'
    },
    // Base URL definitions
    {
      regex: /baseURL\s*:\s*["'](https?:\/\/[^"']+)['"]/g,
      method: 'INFO',
      type: 'base-url'
    },
    // Socket.io connections
    {
      regex: /io\(\s*["'](https?:\/\/[^"']+)['"]\)/g,
      method: 'WS',
      type: 'websocket'
    }
  ];
  
  patterns.forEach(pattern => {
    try {
      let matches;
      if (pattern.regex.global) {
        // Handle global regex patterns
        while ((matches = pattern.regex.exec(jsContent)) !== null) {
          try {
            extractApiFromMatch(matches, pattern, baseUrl, apis);
          } catch (e) {
            // Skip any errors in individual matches
          }
        }
      } else {
        // Handle non-global regex patterns
        matches = jsContent.match(pattern.regex);
        if (matches) {
          matches.forEach(match => {
            try {
              extractApiFromMatch([match], pattern, baseUrl, apis);
            } catch (e) {
              // Skip any errors in individual matches
            }
          });
        }
      }
    } catch (e) {
      // Skip any errors in pattern processing
    }
  });
  
  return apis;
}

// Helper function to extract API info from regex matches
function extractApiFromMatch(match, pattern, baseUrl, apis) {
  let url, method;
  
  if (pattern.method === 'dynamic') {
    if (pattern.methodIndex !== undefined && pattern.urlIndex !== undefined) {
      method = match[pattern.methodIndex].toUpperCase();
      url = match[pattern.urlIndex];
    } else {
      url = match[1];
      method = match[2] ? match[2].toUpperCase() : 'GET';
    }
  } else {
    url = match[1];
    method = pattern.method;
  }
  
  // Handle relative URLs
  if (url && !url.startsWith('http')) {
    try {
      url = new URL(url, baseUrl).href;
    } catch (e) {
      // Skip invalid URLs
      return;
    }
  }
  
  // If we've determined this is a valid URL, add it to the APIs list
  if (url && isValidUrl(url)) {
    apis.push({
      url: url,
      method: method,
      source: baseUrl,
      type: pattern.type
    });
  }
}

// Find API endpoints in HTML content
function findApiEndpoints($, targetUrl, htmlContent) {
  const apis = [];
  
  // Look for API links in HTML
  $('a[href*="api"], a[href*="json"], a[href*="xml"], a[href*="graphql"]').each((i, el) => {
    try {
      const href = $(el).attr('href');
      if (!href) return;
      
      // Make URL absolute
      const fullUrl = new URL(href, targetUrl).href;
      
      // Check if the URL is a known JSON API
      const isKnownJsonApi = fullUrl.includes('dummyjson.com') || 
                            fullUrl.includes('jsonplaceholder.typicode.com') ||
                            fullUrl.includes('randomuser.me/api');
      
      apis.push({
        url: fullUrl,
        text: $(el).text().trim() || href,
        method: 'GET',
        source: targetUrl,
        type: isKnownJsonApi ? 'json-api' : 'link'
      });
    } catch (e) {
      // Skip invalid URLs
    }
  });
  
  // Look for API URLs in comments
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let commentMatch;
  while ((commentMatch = commentRegex.exec(htmlContent)) !== null) {
    const commentContent = commentMatch[1];
    
    // Look for URLs in comments
    const urlRegex = /(https?:\/\/[^\s'"]+)/g;
    let urlMatch;
    while ((urlMatch = urlRegex.exec(commentContent)) !== null) {
      const url = urlMatch[1];
      if (isApiLikeUrl(url) && isValidUrl(url)) {
        apis.push({
          url: url,
          method: 'GET',
          source: 'HTML comment',
          type: 'comment',
          notes: 'Found in HTML comment'
        });
      }
    }
  }
  
  return apis;
}

// Remove duplicate APIs from an array of API objects
function removeDuplicateApis(apis) {
  const uniqueApis = [];
  const apiUrls = new Set();
  
  apis.forEach(api => {
    if (!apiUrls.has(api.url)) {
      apiUrls.add(api.url);
      uniqueApis.push(api);
    }
  });
  
  return uniqueApis;
}

// Helper function to check if a URL is valid
function isValidUrl(url) {
  try {
    // Check if the URL has a protocol
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      return false;
    }
    
    // Try to create a URL object
    new URL(url);
    return true;
  } catch (e) {
    return false;
  }
}

// Export crawl data to JSON
ipcMain.on('export-data', async (event, data) => {
  try {
    const filePath = path.join(app.getPath('downloads'), `api-crawl-${Date.now()}.json`);
    await promisify(fs.writeFile)(filePath, JSON.stringify(data, null, 2));
    event.reply('export-complete', { success: true, filePath });
  } catch (error) {
    console.error('Error exporting data:', error);
    event.reply('export-complete', { success: false, error: error.message });
  }
});