rule Malware_Evasion_Bypass
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 74 12 6A 5B 5A 8B CE E8 25 05 00 00 CA ?? ?? ?? ?? }
        $pattern1 = { 8D 95 F0 FE FF 89 9D F0 FE FF 8B CE E8 74 FA FF FF CA ?? ?? ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 C8 FF FF FF CA 00 40 E7 C3 }

    condition:
        any of them
}