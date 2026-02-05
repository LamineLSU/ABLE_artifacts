rule MalwareEvasion
{
    meta:
        description = "Detects evasion techniques involving window visibility checks and system notifications"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"
        author = "Cybersecurity Analyst"
        date = "2023-10-15"

    strings:
        $pattern0 = { FF 15 ?? ?? ?? ?? 85 C0 74 10 }  // IsWindowVisible check + conditional jump
        $pattern1 = { 6A 00 FF 15 ?? ?? ?? ?? }        // Push 0 + Shell_NotifyIconA call
        $pattern2 = { 6A 09 FF 15 ?? ?? ?? ?? }        // Push 9 + ShowWindow call

    condition:
        any of them
}