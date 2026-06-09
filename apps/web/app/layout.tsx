import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "RiskRadar · Watch Commander for supply-chain security",
  description:
    "RiskRadar finds the CVEs that reach your code, lets Codex write the fix, signs the result, and waits for a human tap. Open-source, with real, live integrations.",
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/icon.png", type: "image/png" },
    ],
    apple: "/icon.png",
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
