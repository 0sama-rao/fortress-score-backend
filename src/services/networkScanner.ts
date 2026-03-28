import { execFile } from "child_process";
import { promisify } from "util";
import { XMLParser } from "fast-xml-parser";
import type { NetworkSignals } from "../types/scoring.js";

const execFileAsync = promisify(execFile);
const NMAP_TIMEOUT = 300000; // 5 minutes

// Ports to scan
const TARGET_PORTS = "22,23,25,80,443,445,1433,3306,3389,5432,5900,6379,8080,8443,27017";

// Critical service ports
const CRITICAL_PORTS: Record<number, string> = {
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
    dbPortsExposed: false,
  };

  try {
    // -sT: TCP connect scan (no root required, AWS-safe)
    // -p: specific ports
    // --open: only show open ports
    // -oX -: output XML to stdout
    const { stdout } = await execFileAsync(
      "nmap",
      ["-sT", `-p${TARGET_PORTS}`, "--open", "-oX", "-", hostname],
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

    const dbPorts = [1433, 3306, 5432, 6379, 27017];
    signals.dbPortsExposed = signals.openPorts.some((p) => dbPorts.includes(p));
  } catch {
    // nmap failed or timed out — return empty signals
  }

  return signals;
}
