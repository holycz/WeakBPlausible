'use strict'

const fs = require('fs')
const http = require('http')
const https = require('https')
const path = require('path')
const request = require('/workspace/request')

function inject (candidatePath, targetPath) {
  const candidate = fs.readFileSync(candidatePath, 'utf8')
  const target = fs.readFileSync(targetPath, 'utf8')
  const start = candidate.indexOf('  function processRedirect (shouldRedirect) {')
  let end = candidate.indexOf('\n  function checkRedirectUri', start)
  if (end < 0) end = candidate.length
  if (start < 0) throw new Error('candidate does not contain an injectable processRedirect function')
  const replacement = candidate.slice(start, end)
  const targetStart = target.indexOf('  function processRedirect (shouldRedirect) {')
  const targetEnd = target.indexOf('\n  // test allowRedirect arity', targetStart)
  if (targetStart < 0 || targetEnd < 0) throw new Error('target redirect function markers not found')
  fs.writeFileSync(targetPath, target.slice(0, targetStart) + replacement + target.slice(targetEnd), 'utf8')
}

function requestOnce (uri) {
  return new Promise((resolve, reject) => {
    request({ uri, followRedirect: true, timeout: 3000 }, (err, response, body) => {
      if (err) return reject(err)
      resolve({ statusCode: response && response.statusCode, body: String(body || '') })
    })
  })
}

async function test (root) {
  const key = fs.readFileSync(path.join(root, 'tests/ssl/ca/localhost.key'))
  const cert = fs.readFileSync(path.join(root, 'tests/ssl/ca/localhost.crt'))
  const httpsServer = https.createServer({ key, cert }, (req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain' })
    res.end('internal-target')
  })
  const httpServer = http.createServer((req, res) => {
    const target = `https://localhost:${httpsServer.address().port}/internal`
    res.writeHead(302, { location: target })
    res.end()
  })
  await new Promise(resolve => httpsServer.listen(0, '127.0.0.1', resolve))
  await new Promise(resolve => httpServer.listen(0, '127.0.0.1', resolve))
  const uri = `http://localhost:${httpServer.address().port}/redirect`
  const oldTls = process.env.NODE_TLS_REJECT_UNAUTHORIZED
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'
  try {
    try {
      const result = await requestOnce(uri)
      const followed = result.body === 'internal-target'
      console.log(JSON.stringify({ case: 'cross_protocol_redirect', uri, followed, blocked: false, result }))
      // The fixed behavior must not silently follow this cross-protocol hop.
      if (followed) process.exitCode = 20
    } catch (err) {
      const blocked = /ERR_INVALID_PROTOCOL|Protocol .* not supported|Cannot follow redirects across protocols/i.test(String(err && err.stack))
      console.log(JSON.stringify({ case: 'cross_protocol_redirect', uri, followed: false, blocked, error: String(err && err.message) }))
      if (!blocked) process.exitCode = 21
    }
  } finally {
    if (oldTls === undefined) delete process.env.NODE_TLS_REJECT_UNAUTHORIZED
    else process.env.NODE_TLS_REJECT_UNAUTHORIZED = oldTls
    await new Promise(resolve => httpServer.close(resolve))
    await new Promise(resolve => httpsServer.close(resolve))
  }
}

if (process.argv[2] === 'inject') inject(process.argv[3], process.argv[4])
else if (process.argv[2] === 'test') test(process.argv[3]).catch(err => { console.error(err.stack); process.exitCode = 21 })
else throw new Error('usage: inject CANDIDATE TARGET | test ROOT')
