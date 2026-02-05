rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Multiple bypass paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 4C ?? ?? ?? ?? ?? 59 E5 }
        $pattern1 = { 74 0A 8B 00 ?? ?? ?? ?? 6A 5E 5D 5C 5B 5A 50 EC ?? ?? ?? ?? }
        $pattern2 = { 83 C4 00 00 00 00 E8 FC ?? ?? ?? ?? 8B 45 ?? }

    condition:
        any of them
}