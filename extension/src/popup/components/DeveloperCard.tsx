/**
 * PhishGuard — DeveloperCard Component
 *
 * Elegant developer attribution card used in the Options/About page.
 * Premium minimal style — not a watermark, a signature.
 *
 * Author: Akshay | https://akshay.fruvvi.com
 */

interface DeveloperLink {
  label: string;
  href: string;
  icon: string;  // Unicode/emoji icon
}

const LINKS: DeveloperLink[] = [
  { label: "Portfolio",  href: "https://akshay.fruvvi.com",                              icon: "◈" },
  { label: "GitHub",     href: "https://github.com/Akshay-core",                          icon: "⌥" },
  { label: "LinkedIn",   href: "https://linkedin.com/in/akshay-tb-791bb4372",             icon: "⊞" },
  { label: "Instagram",  href: "https://www.instagram.com/akshayyyy_2007",                icon: "◉" },
];

export function DeveloperCard() {
  const openLink = (href: string) => {
    chrome.tabs.create({ url: href });
  };

  return (
    <div
      className="rounded-xl p-4 mt-auto"
      style={{
        background: "#161923",
        border: "1px solid rgba(255,255,255,0.07)",
      }}
    >
      {/* Avatar + identity */}
      <div className="flex items-center gap-3 mb-3">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold shrink-0"
          style={{
            background: "linear-gradient(135deg, #6366f1 0%, #818cf8 100%)",
            color: "#fff",
          }}
        >
          AK
        </div>
        <div>
          <p className="text-[13px] font-semibold" style={{ color: "#f0f2f5" }}>
            Akshay
          </p>
          <p className="text-[11px]" style={{ color: "#4d5566" }}>
            Cybersecurity Engineer · Privacy-First AI
          </p>
        </div>
      </div>

      {/* Links */}
      <div className="flex flex-wrap gap-1.5">
        {LINKS.map((link) => (
          <button
            key={link.label}
            onClick={() => openLink(link.href)}
            className="flex items-center gap-1.5 rounded px-2.5 py-1 text-[11px] transition-all duration-150"
            style={{
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.07)",
              color: "#8892a4",
            }}
            onMouseEnter={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background = "rgba(99,102,241,0.12)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(99,102,241,0.30)";
              (e.currentTarget as HTMLButtonElement).style.color = "#818cf8";
            }}
            onMouseLeave={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.04)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.07)";
              (e.currentTarget as HTMLButtonElement).style.color = "#8892a4";
            }}
          >
            <span aria-hidden="true" style={{ fontSize: 10 }}>{link.icon}</span>
            {link.label}
          </button>
        ))}
      </div>
    </div>
  );
}
