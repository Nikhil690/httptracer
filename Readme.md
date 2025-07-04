# HTTPTracer

HTTPTracer is a tool for tracing and debugging HTTP requests and responses in your applications.

## Features

- Logs HTTP requests and responses
- Supports multiple output formats
- Easy integration with existing projects

## Requirements

- Go 1.18+ (or compatible)
- Git

## Installation

Clone the repository:

```bash
git clone https://github.com/Nikhil690/httptracer.git
cd httptracer
```

Install dependencies:

```bash
go mod tidy
```

## Directory Structure

- `http/` &mdash; A simple HTTP demo application.
- `tracehttp/` &mdash; The HTTPTracer tool.

## Usage

### 1. Run the Demo HTTP App

In one terminal, start the demo app:

```bash
cd http
./dummy
```

This will start a sample HTTP server (default: `localhost:8084`).

### 2. Run HTTPTracer

In another terminal, run the tracer and pass the demo app binary name as an argument:

```bash
cd ../tracehttp
./ht dummy
```

### 3. Send a Test Request

In a third terminal, send a request:

```bash
curl "http://localhost:8084/?input=this+should+be+traced"
```

You should see the request and response logged by HTTPTracer.

## cleanup 

```bash
sudo rm /sys/fs/bpf/pid_map
```