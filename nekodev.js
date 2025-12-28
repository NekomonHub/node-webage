#!/usr/bin/env node

import fetch from 'node-fetch'
import chalk from 'chalk'
import { URL } from 'url'
import fs from 'fs'
import { spawn } from 'child_process'
import open from 'open'
const magenta = chalk.bold.magenta
const white = chalk.white

function banner() {
  console.log(magenta(fs.readFileSync('./logox','utf8')));
  console.log(white('Node-WebAge Scanner - PhisherScanner\n'))
}

function extractDomain(input) {
  try {
    const url = input.startsWith('http')
      ? new URL(input)
      : new URL(`http://${input}`)
    return url.hostname.replace(/^www\./, '')
  } catch {
    return null
  }
}

function getRootDomain(domain) {
  const platforms = [
    'vercel.app',
    'netlify.app',
    'github.io',
    'pages.dev',
    'onrender.com'
  ]

  for (const p of platforms) {
    if (domain === p || domain.endsWith(`.${p}`)) {
      return {
        root: p,
        platform: true
      }
    }
  }

  return {
    root: domain,
    platform: false
  }
}

function daysBetween(date) {
  return Math.floor((Date.now() - date.getTime()) / 86400000)
}

function verdict(days) {
  if (days < 30) return 'PHISHING HIGH RISK'
  if (days < 180) return 'SUSPICIOUS'
  if (days < 365) return 'LOW TRUST'
  return 'LIKELY LEGIT'
}

function score(days, platform) {
  let base
  if (days < 30) base = 90
  else if (days < 180) base = 65
  else if (days < 365) base = 35
  else base = 10

  if (platform) base += 15
  return Math.min(base, 100)
}

async function rdapLookup(domain) {
  const url = `https://rdap.org/domain/${domain}`
  const res = await fetch(url, { timeout: 15000 })
  if (!res.ok) {
    throw new Error('RDAP lookup failed or domain not registered')
  }

  const data = await res.json()
  const event = data.events?.find(e => e.eventAction === 'registration')
  if (!event) {
    throw new Error('Registration date not found in RDAP')
  }
  return new Date(event.eventDate)
} async function main() {
  clear();
  open('https://whatsapp.com/channel/0029VbBfxxx6rsQuLbCV670u');
  await wait(500);
  banner();
  const input = process.argv[2]
  if (!input) {
    console.log(white('Usage: node node-webage.js <url | domain>\n'))
    process.exit(1)
  }
  const domain = extractDomain(input)
  if (!domain) {
    console.log(magenta('[X] Invalid URL or domain'))
    process.exit(1)
  }
  const { root, platform } = getRootDomain(domain)
  console.log(white(`Target Domain : ${domain}`))
  if (platform) {
    console.log(magenta('[!] Platform Subdomain Detected'))
    console.log(white(`Base Domain   : ${root}`))
    console.log(magenta('[!] WARNING: Anyone can create subdomains on this platform\n'))
  }
  console.log(white('Query RDAP WHOIS...\n'))
  try {
    
    const created = await rdapLookup(root)
    const ageDays = daysBetween(created)
    const risk = verdict(ageDays)
    const riskScore = score(ageDays, platform)
    console.log(magenta('──── Domain Age Report ────'))
    console.log(white(`Registered Domain : ${root}`))
    console.log(white(`Created Date      : ${created.toISOString()}`))
    console.log(white(`Domain Age        : ${ageDays} days`))
    console.log(white(`Risk Score        : ${riskScore}/100`))
    console.log(white(`Verdict           : ${risk}`))
    if (platform) {
      console.log(magenta('\n[!] NOTE'))
      console.log(white('Legitimate platform domain does NOT mean the site is legitimate.'))
      console.log(white('Subdomains are disposable and heavily abused for phishing.'))
    } if (ageDays < 30) {
      console.log(magenta('\n[!] RED FLAG'))
      console.log(white('Newly registered domain. Extremely common in phishing campaigns.'))
    }
  } catch (err) {
    console.log(magenta('[X] Error:'), white(err.message))
  }
} main();
function wait(ms){return new Promise(resolve => setTimeout(resolve,ms));}
function clear(){spawn('clear',{stdio:"inherit"});}
