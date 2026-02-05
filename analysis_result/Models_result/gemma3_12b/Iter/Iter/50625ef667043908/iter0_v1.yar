rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // Trace //1 - Conditional Jump
        $pattern1 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Trace //1 - Function Call
        $pattern2 = { 83 F8 01 74 20 FF 75 08 E8 ?? ?? ?? ?? } // Trace //2 - Conditional Jump

    condition:
        any of them
}