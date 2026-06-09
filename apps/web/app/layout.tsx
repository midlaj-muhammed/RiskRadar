import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "RiskRadar · Watch Commander for supply-chain security",
  description:
    "RiskRadar finds the CVEs that reach your code, lets Codex write the fix, signs the result, and waits for a human tap. Open-source, with real, live integrations.",
  icons: [
    {
      rel: "icon",
      url: "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA2NCA2NCIgZmlsbD0ibm9uZSI+CiAgPCEtLSBCcmFuZCBjYW52YXM6IHdhcm0gZGFyayAoLS1iZyAjMGQwZDBjKSB3aXRoIHRoZSBzYW1lIDEyLTE0cHggY29ybmVyIHJvdW5kaW5nIHVzZWQgb24gLmNhcmQvLnBhbmVsLiAtLT4KICA8cmVjdCB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHJ4PSIxNCIgZmlsbD0iIzBkMGQwYyIvPgogIDwhLS0gU2hpZWxkOiBmaWxsZWQgd2l0aCBzdXJmYWNlLCBvdXRsaW5lZCB3aXRoIGEgc2luZ2xlIGhhaXJsaW5lIHNvIGRlcHRoIGNvbWVzIGZyb20gY29udHJhc3QsIG5vdCBzaGFkb3cuIC0tPgogIDxwYXRoIGQ9Ik0zMiA4IEw1MiAxNS41IFYzMS41IEM1MiA0My41IDQzLjggNTEgMzIgNTYgQzIwLjIgNTEgMTIgNDMuNSAxMiAzMS41IFYxNS41IFoiCiAgICAgICAgZmlsbD0iIzE2MTUxMyIgc3Ryb2tlPSIjMzYzNDJkIiBzdHJva2Utd2lkdGg9IjIiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KICA8IS0tIFB1bHNlIGxpbmUgaW4gQ3Vyc29yIE9yYW5nZSAtIHNpbmdsZSBjbGVhciBwZWFrIHNvIGl0IHJlYWRzIGF0IDE2cHguIC0tPgogIDxwYXRoIGQ9Ik0xNyAzMyBIMjQuNSBMMjguNSAyMiBMMzMgNDMgTDM3IDI3IEw0MC41IDMzIEg0NyIKICAgICAgICBzdHJva2U9IiNmNTRlMDAiIHN0cm9rZS13aWR0aD0iMy41IiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiLz4KICA8IS0tIFRoZSBicmFuZCBkb3QsIHR1Y2tlZCBpbnRvIHRoZSBzaGllbGQncyBjcm93biBzbyB0aGUgZmF2aWNvbiBtYXRjaGVzIHRoZSBzaWRlYmFyIHdvcmRtYXJrLiAtLT4KICA8Y2lyY2xlIGN4PSIzMiIgY3k9IjE0LjUiIHI9IjEuOCIgZmlsbD0iI2Y1NGUwMCIvPgo8L3N2Zz4=",
      type: "image/svg+xml",
    },
  ],
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
