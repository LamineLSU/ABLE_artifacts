rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - specific function calls and security checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 25 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern1 = { E8 74 ?? ?? ?? ?? 0F 84 ?? ?? ?? ?? 8B 45 ?? }
        $pattern2 = { E8 C8 FF ?? ?? ?? ?? AC B0 41 00 }

    condition:
        any of them
}