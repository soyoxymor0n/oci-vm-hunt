#!/usr/bin/env node
// Hunts for Oracle Cloud "Always Free" Ampere A1 capacity and creates the VM
// configured through environment variables the moment a slot is free.
//
// Why a script: A1 capacity in a region comes and goes; the console says "Out of host
// capacity" and the only fix is to try again later. This tries, and stops asking once
// the instance exists. Run it from the scheduled workflow .github/workflows/hunt.yml.
//
// Exit codes: 0 = instance exists / was created / no capacity right now (try again later),
//             1 = a real error (bad credentials, bad request) - the workflow turns red.
//
// Auth is the OCI API signing key (NOT the console password): see README.md.
// Zero dependencies - requests are signed with node:crypto (draft-cavage HTTP signatures).
//
//   node tools/oci-grab-vm.mjs            # create network if missing, try to launch
//   node tools/oci-grab-vm.mjs --check    # only report: does the instance exist? (no writes)
import { createHash, createSign } from 'node:crypto';
import { appendFileSync } from 'node:fs';

const CONFIG = {
  // Values come from oracle-cloud-vm-settings-main.tf; every one can be overridden by env.
  // Size is 2 OCPU / 12 GB, not the .tf's 4 / 24: Oracle's 2026 Always Free A1 allowance is 2 / 12
  // and anything above it bills on a Pay As You Go account.
  region: 'eu-frankfurt-1',
  compartmentId: '', // defaults to OCI_TENANCY_OCID
  availabilityDomain: '', // optional: tried first, then the region's other domains
  displayName: 'instance-20260328-2333',
  shape: 'VM.Standard.A1.Flex',
  ocpus: 2,
  memoryInGBs: 12,
  imageId: '',
  vcnName: 'vcn-20260328-2336',
  vcnDnsLabel: 'vcn03282336',
  subnetName: 'subnet-20260328-2336',
  subnetDnsLabel: 'subnet03282336',
  gatewayName: 'Internet Gateway vcn-20260328-2336',
  vnicName: 'regopsvnic',
  sshKey: '',
  // The .tf says "false". A VM without a public address has no way out (the template has an
  // internet gateway, not a NAT gateway) and cannot be reached over SSH, so the default here is
  // true. Set OCI_ASSIGN_PUBLIC_IP=false to follow the .tf literally.
  assignPublicIp: true,
  // Always Free A1 must live in the home region, but that region has several availability
  // domains with separate capacity: try the configured one first, then the others. A 1 OCPU /
  // 6 GB launch is also tried (flex shapes can be resized later in the console).
  tryAllDomains: true,
  allowSmaller: true,
};

export function configFromEnv(env = process.env) {
  const c = { ...CONFIG };
  const str = (k, name) => { if (env[name]) c[k] = env[name]; };
  str('region', 'OCI_REGION');
  str('compartmentId', 'OCI_COMPARTMENT_OCID');
  str('availabilityDomain', 'OCI_AVAILABILITY_DOMAIN');
  str('displayName', 'OCI_INSTANCE_NAME');
  str('imageId', 'OCI_IMAGE_OCID');
  str('sshKey', 'OCI_SSH_PUBLIC_KEY');
  if (env.OCI_OCPUS) c.ocpus = Number(env.OCI_OCPUS);
  if (env.OCI_MEMORY_GB) c.memoryInGBs = Number(env.OCI_MEMORY_GB);
  if (env.OCI_TRY_ALL_DOMAINS) c.tryAllDomains = env.OCI_TRY_ALL_DOMAINS !== 'false';
  if (env.OCI_ALLOW_SMALLER) c.allowSmaller = env.OCI_ALLOW_SMALLER !== 'false';
  if (env.OCI_ASSIGN_PUBLIC_IP) c.assignPublicIp = env.OCI_ASSIGN_PUBLIC_IP !== 'false';
  if (!c.compartmentId && env.OCI_TENANCY_OCID) c.compartmentId = env.OCI_TENANCY_OCID;
  return c;
}

/** "Out of host capacity" (HTTP 500) and throttling (429) mean "try again later", not "broken". */
export function isNoCapacity(status, body) {
  const text = typeof body === 'string' ? body : JSON.stringify(body ?? '');
  if (status === 429) return true;
  return status === 500 && /capacity|LimitExceeded|out of host/i.test(text);
}

/** Authorization header value for OCI's HTTP signature scheme. */
export function signRequest({ method, url, body, keyId, privateKeyPem, now = new Date() }) {
  const u = new URL(url);
  const lower = method.toLowerCase();
  const headers = {
    date: now.toUTCString(),
    host: u.host,
  };
  const signed = ['(request-target)', 'date', 'host'];
  if (['post', 'put', 'patch'].includes(lower)) {
    const payload = body ?? '';
    headers['content-type'] = 'application/json';
    headers['content-length'] = String(Buffer.byteLength(payload));
    headers['x-content-sha256'] = createHash('sha256').update(payload).digest('base64');
    signed.push('x-content-sha256', 'content-type', 'content-length');
  }
  const lines = signed.map((h) => (h === '(request-target)'
    ? `(request-target): ${lower} ${u.pathname}${u.search}`
    : `${h}: ${headers[h]}`));
  const signature = createSign('RSA-SHA256').update(lines.join('\n')).sign(privateKeyPem, 'base64');
  headers.authorization = `Signature version="1",keyId="${keyId}",algorithm="rsa-sha256",headers="${signed.join(' ')}",signature="${signature}"`;
  return headers;
}

class Api {
  constructor(cfg, auth, fetchImpl) {
    this.base = `https://iaas.${cfg.region}.oraclecloud.com/20160918`;
    this.auth = auth;
    this.fetch = fetchImpl;
  }
  async call(method, path, body) {
    const url = path.startsWith('https://') ? path : `${this.base}${path}`;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const headers = signRequest({ method, url, body: payload, keyId: this.auth.keyId, privateKeyPem: this.auth.privateKeyPem });
    const res = await this.fetch(url, { method, headers, body: payload });
    const text = await res.text();
    let json = null;
    try { json = text ? JSON.parse(text) : null; } catch { json = text; }
    return { status: res.status, ok: res.ok, body: json };
  }
}

function must(r, what) {
  if (!r.ok) throw new Error(`${what} failed: HTTP ${r.status} ${JSON.stringify(r.body)}`);
  return r.body;
}

const q = (o) => Object.entries(o).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');

/** Existing, not-terminated instance with the configured name, or null. */
async function findInstance(api, cfg) {
  const list = must(await api.call('GET', `/instances?${q({ compartmentId: cfg.compartmentId, displayName: cfg.displayName })}`), 'list instances');
  return list.find((i) => !['TERMINATING', 'TERMINATED'].includes(i.lifecycleState)) ?? null;
}

/** Find-or-create VCN, internet gateway + default route, and subnet. Returns the subnet id. */
async function ensureNetwork(api, cfg, log) {
  const vcns = must(await api.call('GET', `/vcns?${q({ compartmentId: cfg.compartmentId, displayName: cfg.vcnName })}`), 'list vcns');
  let vcn = vcns.find((v) => v.lifecycleState === 'AVAILABLE');
  if (!vcn) {
    log(`creating VCN ${cfg.vcnName}`);
    vcn = must(await api.call('POST', '/vcns', {
      cidrBlock: '10.0.0.0/16', compartmentId: cfg.compartmentId, displayName: cfg.vcnName, dnsLabel: cfg.vcnDnsLabel,
    }), 'create vcn');
  }
  const gws = must(await api.call('GET', `/internetGateways?${q({ compartmentId: cfg.compartmentId, vcnId: vcn.id })}`), 'list gateways');
  let gw = gws.find((g) => g.lifecycleState === 'AVAILABLE');
  if (!gw) {
    log('creating internet gateway');
    gw = must(await api.call('POST', '/internetGateways', {
      compartmentId: cfg.compartmentId, vcnId: vcn.id, isEnabled: true, displayName: cfg.gatewayName,
    }), 'create gateway');
  }
  const rt = must(await api.call('GET', `/routeTables/${vcn.defaultRouteTableId}`), 'get route table');
  if (!(rt.routeRules ?? []).some((r) => r.destination === '0.0.0.0/0')) {
    log('adding default route to the internet gateway');
    must(await api.call('PUT', `/routeTables/${vcn.defaultRouteTableId}`, {
      routeRules: [{ destination: '0.0.0.0/0', destinationType: 'CIDR_BLOCK', networkEntityId: gw.id }],
    }), 'update route table');
  }
  const subnets = must(await api.call('GET', `/subnets?${q({ compartmentId: cfg.compartmentId, vcnId: vcn.id })}`), 'list subnets');
  let subnet = subnets.find((s) => s.lifecycleState === 'AVAILABLE');
  if (!subnet) {
    log(`creating subnet ${cfg.subnetName}`);
    subnet = must(await api.call('POST', '/subnets', {
      cidrBlock: '10.0.0.0/24', compartmentId: cfg.compartmentId, vcnId: vcn.id, displayName: cfg.subnetName,
      dnsLabel: cfg.subnetDnsLabel, routeTableId: vcn.defaultRouteTableId,
    }), 'create subnet');
  }
  return subnet.id;
}

/** Configured domain first, then the rest of the region's domains. */
async function domainsToTry(api, cfg) {
  if (!cfg.tryAllDomains) return [cfg.availabilityDomain].filter(Boolean);
  const r = await api.call('GET', `https://identity.${cfg.region}.oraclecloud.com/20160918/availabilityDomains?${q({ compartmentId: cfg.compartmentId })}`);
  if (!r.ok || !Array.isArray(r.body)) return [cfg.availabilityDomain].filter(Boolean);
  const others = r.body.map((d) => d.name).filter((n) => n !== cfg.availabilityDomain);
  return [cfg.availabilityDomain, ...others].filter(Boolean);
}

function launchBody(cfg, subnetId) {
  const plugin = (name, on) => ({ name, desiredState: on ? 'ENABLED' : 'DISABLED' });
  return {
    availabilityDomain: cfg.availabilityDomain,
    compartmentId: cfg.compartmentId,
    displayName: cfg.displayName,
    shape: cfg.shape,
    shapeConfig: { ocpus: cfg.ocpus, memoryInGBs: cfg.memoryInGBs },
    sourceDetails: { sourceType: 'image', imageId: cfg.imageId },
    createVnicDetails: {
      subnetId, displayName: cfg.vnicName, assignPublicIp: cfg.assignPublicIp,
      assignIpv6Ip: false, assignPrivateDnsRecord: true,
    },
    metadata: { ssh_authorized_keys: cfg.sshKey },
    availabilityConfig: { recoveryAction: 'RESTORE_INSTANCE' },
    isPvEncryptionInTransitEnabled: true,
    instanceOptions: { areLegacyImdsEndpointsDisabled: false },
    agentConfig: {
      isManagementDisabled: false,
      isMonitoringDisabled: false,
      pluginsConfig: [
        plugin('Vulnerability Scanning', false), plugin('Management Agent', false),
        plugin('Custom Logs Monitoring', true), plugin('Compute RDMA GPU Monitoring', false),
        plugin('Compute Instance Monitoring', true), plugin('Compute HPC RDMA Auto-Configuration', false),
        plugin('Compute HPC RDMA Authentication', false), plugin('Cloud Guard Workload Protection', true),
        plugin('Block Volume Management', false), plugin('Bastion', false),
      ],
    },
  };
}

/**
 * One attempt. Returns { state: 'exists' | 'created' | 'no-capacity' | 'missing', ... }.
 * `check` reads only; it never creates the network or the instance.
 */
export async function attempt({ cfg, auth, fetchImpl = fetch, check = false, log = console.log }) {
  const api = new Api(cfg, auth, fetchImpl);
  const existing = await findInstance(api, cfg);
  if (existing) return { state: 'exists', id: existing.id, lifecycle: existing.lifecycleState };
  if (check) return { state: 'missing' };

  const subnetId = await ensureNetwork(api, cfg, log);
  const domains = await domainsToTry(api, cfg);
  const sizes = [{ ocpus: cfg.ocpus, memoryInGBs: cfg.memoryInGBs }];
  if (cfg.allowSmaller && cfg.ocpus > 1) sizes.push({ ocpus: 1, memoryInGBs: 6 });
  let last = null;
  for (const size of sizes) {
    for (const availabilityDomain of domains) {
      const body = launchBody({ ...cfg, ...size, availabilityDomain }, subnetId);
      const res = await api.call('POST', '/instances', body);
      if (res.ok) {
        return { state: 'created', id: res.body.id, lifecycle: res.body.lifecycleState, availabilityDomain, ...size };
      }
      if (!isNoCapacity(res.status, res.body)) {
        throw new Error(`launch failed (${availabilityDomain}, ${size.ocpus} OCPU): HTTP ${res.status} ${JSON.stringify(res.body)}`);
      }
      last = res.status;
    }
  }
  return { state: 'no-capacity', status: last, tried: domains.length * sizes.length };
}

function authFromEnv(env = process.env) {
  const need = ['OCI_TENANCY_OCID', 'OCI_USER_OCID', 'OCI_FINGERPRINT', 'OCI_PRIVATE_KEY', 'OCI_IMAGE_OCID', 'OCI_SSH_PUBLIC_KEY'];
  const missing = need.filter((k) => !env[k]);
  if (missing.length) throw new Error(`missing env: ${missing.join(', ')} (see README.md)`);
  const cfg = configFromEnv(env);
  const tenancy = env.OCI_TENANCY_OCID || cfg.compartmentId;
  return {
    cfg,
    auth: {
      keyId: `${tenancy}/${env.OCI_USER_OCID}/${env.OCI_FINGERPRINT}`,
      // Secrets stores often flatten newlines to a literal \n.
      privateKeyPem: env.OCI_PRIVATE_KEY.replace(/\\n/g, '\n'),
    },
  };
}

function setOutput(name, value) {
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `${name}=${value}\n`);
}

async function main() {
  const { cfg, auth } = authFromEnv();
  const result = await attempt({ cfg, auth, check: process.argv.includes('--check') });
  setOutput('state', result.state);
  const msg = {
    exists: `instance already exists (${result.lifecycle})`,
    created: `CREATED an instance (${result.lifecycle}), ${result.ocpus} OCPU / ${result.memoryInGBs} GB. Look it up in the Oracle console.`,
    'no-capacity': `no capacity right now (HTTP ${result.status}, ${result.tried ?? 1} combinations tried); will try again on the next run`,
    missing: 'instance does not exist yet',
  }[result.state];
  console.log(msg);
}

if (process.argv[1]?.endsWith('oci-grab-vm.mjs')) {
  main().catch((e) => { console.error(String(e.message ?? e)); process.exit(1); });
}
