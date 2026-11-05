import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'NexusPanel',
  description: 'Security-first hosting control panel',
};

/**
 * The theme class is applied before first paint (no flash): the inline
 * script reads the persisted preference; dark is the default.
 */
const themeNoFlash = `try{var t=localStorage.getItem('nexuspanel.theme');document.documentElement.dataset.theme=(t==='light'?'light':'dark');}catch(e){document.documentElement.dataset.theme='dark';}`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        {/* Runtime webfont with full system-font fallback if unreachable */}
        <link
          rel="stylesheet"
          href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,400;14..32,500;14..32,600;14..32,700;14..32,800&family=JetBrains+Mono:wght@400;600&display=swap"
        />
        <script dangerouslySetInnerHTML={{ __html: themeNoFlash }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
