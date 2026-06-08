"use client";

import { usePathname } from "next/navigation";
import { Activity, Bell, Boxes, CheckSquare, Eye, Gauge, GitPullRequest, Radar, ReceiptText, ScanLine, Settings, Shield, SquareStack } from "lucide-react";

const NAV = [
  ["/dashboard", "Watch Commander", Gauge],
  ["/threat-radar", "Threat Radar", Radar],
  ["/scanners", "Scanner Coverage", ScanLine],
  ["/watch", "Watch Mode", Eye],
  ["/providers", "Providers", Boxes],
  ["/blast-radius", "Blast Radius", SquareStack],
  ["/projects", "Projects", Shield],
  ["/findings", "Findings", Activity],
  ["/remediations", "Remediation Jobs", GitPullRequest],
  ["/approvals", "Approvals", Bell],
  ["/approval-queue", "Approval Queue", CheckSquare],
  ["/audit", "Audit Receipts", ReceiptText],
  ["/settings", "Settings", Settings]
] as const;

export function SideNav() {
  const pathname = usePathname();
  return (
    <nav className="nav">
      {NAV.map(([href, label, Icon]) => {
        const active = pathname === href || pathname.startsWith(`${href}/`);
        return (
          <a key={href} href={href} className={active ? "active" : undefined} aria-current={active ? "page" : undefined}>
            <Icon size={16} />
            {label}
          </a>
        );
      })}
    </nav>
  );
}
