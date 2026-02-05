rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypass register check
        $pattern1 = { 8B CE E8 ?? ?? ?? ?? 85 C0 0F 84 ?? ?? ?? ?? } // Bypass call to 0008667F
        $pattern2 = { 55 8B EC FF 75 08 E8 ?? ?? ?? ?? 59 FF 75 08 FF 15 ?? ?? ?? ?? } // Bypass call to 0040E7C3

    condition:
        any of them
}