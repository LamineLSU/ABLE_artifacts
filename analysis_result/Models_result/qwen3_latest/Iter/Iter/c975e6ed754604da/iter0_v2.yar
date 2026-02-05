rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? ?? ?? ?? 59 }          // CRT ExitProcess call + pop ecx
        $pattern1 = { FF 75 08 FF 15 ?? ?? ?? ?? } // Push ebp+08h + ExitProcess call
        $pattern2 = { 8B FF 55 8B EC }             // Initial stack frame setup

    condition:
        any of them
}