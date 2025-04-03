# API Web Crawler

An Electron-based desktop application for discovering and testing API endpoints on websites.

## Features

- Crawl websites to discover API endpoints
- Support for authenticated crawling (login to websites)
- Test discovered API endpoints with customizable requests
- View API responses with formatted JSON display
- Rate limiting to avoid overwhelming target servers
- Windows 11-style modern UI

## Installation

### Prerequisites

- Node.js (>=14.x)
- npm or yarn

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/api-web-crawler.git
cd api-web-crawler
```

2. Install dependencies:
```bash
npm install
# or
yarn install
```

## Usage

### Starting the Application

```bash
npm start
# or
yarn start
```

For development with DevTools enabled:
```bash
npm run dev
# or
yarn dev
```

### Building Distributable

To build the application for your platform:
```bash
npm run build
# or
yarn build
```

The built application will be available in the `dist` directory.

### Creating a Single EXE File (Windows)

To create a single-file executable with no console window:

1. Build the Windows version specifically:
```bash
npm run build:win
```

2. Look for the installer in the `dist` directory - it will be named `API Web Crawler Setup x.x.x.exe`

3. The installer will create a standalone executable with no console window when users run it.

#### Notes for Windows Users

- If encountering permission errors during build, try running the command prompt or PowerShell as Administrator
- The `build:win` command sets the `NODE_ENV=production` environment variable which helps hide the console window
- Windows builds are configured to disable code signing by default to avoid errors

#### How It Works

- The build process uses electron-builder's NSIS configuration
- Console window is hidden through the `NODE_ENV=production` environment variable
- The build is configured to package everything into a single installer file
- When installed, the application runs without showing a command prompt

### Basic Workflow

1. Enter a target URL in the input field
2. Click "Crawl Website" to start the discovery process
3. If login is required, fill in credentials in the authentication form
4. View discovered API endpoints in the results section
5. Click on an endpoint to test it
6. View and analyze the response

## License

MIT
