import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'NexusPanel',
  description: 'Security-first hosting control panel',
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
