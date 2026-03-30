import { execFile } from "child_process";
import { promisify } from "util";
import { XMLParser } from "fast-xml-parser";
import type { NetworkSignals } from "../types/scoring.js";

const execFileAsync = promisify(execFile);
const NMAP_TIMEOUT = 60000; // 1 minute max per host

// Ports to scan (added 21 for FTP)
const TARGET_PORTS = "21,22,23,25,80,443,445,1433,3306,3389,5432,5900,6379,8080,8443,27017";
const TOTAL_SCANNED_PORTS = 16;

// Critical service ports
const CRITICAL_PORTS: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  23: "Telnet",
  3389: "RDP",
  5900: "VNC",
  1433: "MSSQL",
  3306: "MySQL",
  5432: "PostgreSQL",
  6379: "Redis",
  27017: "MongoDB",
  445: "SMB",
};

export async function scanNetwork(hostname: string): Promise<NetworkSignals> {
  const signals: NetworkSignals = {
    openPorts: [],
    criticalPortsOpen: [],
    rdpExposed: false,
    sshExposed: false,
    telnetOpen: false,
    ftpOpen: false,
    smbExposed: false,
    dbPortsExposed: false,
    multipleWebPorts: false,
    exposureFactor: 0,
  };

  try {
    // -sT: TCP connect scan (no root required, AWS-safe)
    // -p: specific ports
    // --open: only show open ports
    // -oX -: output XML to stdout
    const { stdout } = await execFileAsync(
      "nmap",
      ["-sT", `-p${TARGET_PORTS}`, "--open", "--host-timeout", "30s", "-T4", "-oX", "-", hostname],
      { timeout: NMAP_TIMEOUT }
    );

    const parser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: "@_",
    });
    const result = parser.parse(stdout);

    // Navigate the nmap XML structure
    const host = result?.nmaprun?.host;
    if (!host) return signals;

    let ports = host?.ports?.port;
    if (!ports) return signals;

    // Normalize to array (single port = object, multiple = array)
    if (!Array.isArray(ports)) ports = [ports];

    for (const port of ports) {
      const portId = parseInt(port["@_portid"], 10);
      const state = port?.state?.["@_state"];

      if (state === "open") {
        signals.openPorts.push(portId);

        if (portId in CRITICAL_PORTS) {
          signals.criticalPortsOpen.push(portId);
        }
      }
    }

    // Set specific flags
    signals.rdpExposed = signals.openPorts.includes(3389);
    signals.sshExposed = signals.openPorts.includes(22);
    signals.telnetOpen = signals.openPorts.includes(23);
    signals.ftpOpen = signals.openPorts.includes(21);
    signals.smbExposed = signals.openPorts.includes(445);

    const dbPorts = [1433, 3306, 5432, 6379, 27017];
    signals.dbPortsExposed = signals.openPorts.some((p) => dbPorts.includes(p));

    // Multiple web ports (more than 2 of 80/443/8080/8443 open)
    const webPorts = [80, 443, 8080, 8443];
    const openWebPorts = signals.openPorts.filter((p) => webPorts.includes(p));
    signals.multipleWebPorts = openWebPorts.length > 2;

    // Exposure factor: ratio of open ports to total scanned ports
    signals.exposureFactor = signals.openPorts.length / TOTAL_SCANNED_PORTS;
  } catch {
    // nmap failed or timed out — return empty signals
  }

  return signals;
}
