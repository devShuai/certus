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
        <path d="M44 17.5 A20 20 0 1 0 51.6 39" fill="none" stroke="#F2F3F7" strokeWidth="4.5" strokeLinecap="round" />
        <path d="M23 32 L31 40 L52 17" fill="none" stroke="#E8B34A" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span className="min-w-0">
        <span className="block truncate text-small font-semibold text-zinc-950 dark:text-white">{label}</span>
        {subtitle && <span className="block truncate text-tiny text-zinc-600 dark:text-zinc-400">{subtitle}</span>}
      </span>
    </div>
  );
}
