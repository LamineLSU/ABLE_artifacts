rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? }  # Bypass first exit check
        $pattern1 = { E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? }  # Bypass second exit path
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }  # Bypass third exit point

    condition:
        any of them
}