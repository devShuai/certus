type AppLogoProps = {
  className?: string;
  label?: string;
  markClassName?: string;
  subtitle?: string;
};

export function AppLogo({
  className = "",
  label = "certus",
  markClassName = "h-9 w-9",
  subtitle,
}: AppLogoProps) {
  return (
    <div className={`flex min-w-0 items-center gap-3 ${className}`}>
      <svg
        className={`shrink-0 ${markClassName}`}
        viewBox="0 0 64 64"
        role="img"
        aria-label="certus 统一认证中心"
      >
        <rect width="64" height="64" rx="14" fill="#14161F" />
        <path
          d="M28 14 H11 A5 5 0 0 0 6 19 V45 A5 5 0 0 0 11 50 H26 L32 38 L22 26 Z"
          fill="none"
          stroke="#F2F3F7"
          strokeWidth="4.5"
          strokeLinejoin="round"
        />
        <path
          d="M36 14 H49 A5 5 0 0 1 54 19 V45 A5 5 0 0 1 49 50 H34 L40 38 L30 26 Z"
          fill="none"
          stroke="#E8B34A"
          strokeWidth="4.5"
          strokeLinejoin="round"
        />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">{label}</span>
        {subtitle && <span className="block truncate text-tiny text-zinc-600 dark:text-zinc-400">{subtitle}</span>}
      </span>
    </div>
  );
}
