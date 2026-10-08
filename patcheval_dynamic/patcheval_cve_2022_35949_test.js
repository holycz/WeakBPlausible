'use strict'

const fs = require('fs')
const path = require('path')

async function body (stream) {
  let out = ''
  for await (const chunk of stream) out += String(chunk)
  return out
}

function inject (source, target) {
  const candidate = fs.readFileSync(source, 'utf8')
  const file = fs.readFileSync(target, 'utf8')
  const start = candidate.indexOf('function makeDispatcher (fn) {')
  if (start < 0) throw new Error('candidate function not found')
  const end = candidate.indexOf('\nmodule.exports', start)
  const replacement = candidate.slice(start, end < 0 ? candidate.length : end)
  const targetStart = file.indexOf('function makeDispatcher (fn) {')
  if (targetStart < 0) throw new Error(`target function not found: ${target}`)
  let depth = 0
  let targetEnd = -1
  for (let i = targetStart; i < file.length; i++) {
    if (file[i] === '{') depth++
    else if (file[i] === '}' && --depth === 0) { targetEnd = i + 1; break }
  }
  if (targetEnd < 0) throw new Error('target function end not found')
  fs.writeFileSync(target, file.slice(0, targetStart) + replacement + file.slice(targetEnd))
}

async function test () {
  const { request, MockAgent, setGlobalDispatcher } = require('/workspace/undici')
  const intended = 'http://intended.example'
  const attacker = 'http://attacker.example'
  const agent = new MockAgent()
  agent.disableNetConnect()
  setGlobalDispatcher(agent)
  agent.get(intended).intercept({ path: /.*/, method: 'GET' }).reply(200, 'intended').persist()
  agent.get(attacker).intercept({ path: /.*/, method: 'GET' }).reply(200, 'attacker').persist()
  const payloads = ['//attacker.example/secret', 'http://attacker.example/secret', ' http://attacker.example/secret', 'HtTp://attacker.example/secret']
  let failures = 0
  for (const payload of payloads) {
    try {
      const res = await request({ origin: intended, path: payload, method: 'GET' })
      const got = await body(res.body)
      if (got !== 'intended') { failures++; console.log(JSON.stringify({ payload, result: got, safe: false })) }
      else console.log(JSON.stringify({ payload, result: got, safe: true }))
    } catch (err) {
      console.log(JSON.stringify({ payload, rejected: true, safe: true, error: err.message }))
    }
  }
  await agent.close()
  if (failures) process.exitCode = 20
}

if (process.argv[2] === 'inject') inject(process.argv[3], process.argv[4])
else if (process.argv[2] === 'inject-test') {
  inject(process.argv[3], process.argv[4])
  test().catch(err => { console.error(err.stack); process.exitCode = 21 })
}
else if (process.argv[2] === 'test') test().catch(err => { console.error(err.stack); process.exitCode = 21 })
else throw new Error('usage: inject SOURCE TARGET | inject-test SOURCE TARGET | test')
