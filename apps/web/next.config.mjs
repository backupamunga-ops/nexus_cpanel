/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The panel UI talks to the control plane at NEXT_PUBLIC_API_BASE (default
  // http://localhost:3000/api/v1) per the API design spec §2.1.
  async rewrites() {
    const apiBase = process.env.CONTROL_PLANE_INTERNAL_URL || 'http://localhost:3000';
    return [
      {
        source: '/api/v1/:path*',
        destination: `${apiBase}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
