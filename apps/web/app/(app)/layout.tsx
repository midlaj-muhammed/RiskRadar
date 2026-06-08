import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";
import { SideNav } from "../../components/SideNav";
import { DemoBanner } from "../../components/DemoBanner";

// The dashboard reads a live JSON database per request, so every page under the
// (app) group must render dynamically — never prerendered at build time, which
// would freeze a stale snapshot of the data.
export const dynamic = "force-dynamic";

export default function AppLayout({ children }: { children: ReactNode }) {
  return (
    <div className="shell">
      <aside className="side">
        <a className="brand" href="/">RiskRadar</a>
        <SideNav />
        <div className="sidebar-foot">
          <ShieldCheck size={15} />
          <span>Live integrations. Anything not configured is labeled clearly, so the dashboard reflects reality.</span>
        </div>
      </aside>
      <main className="main">
        <DemoBanner />
        {children}
      </main>
    </div>
  );
}
