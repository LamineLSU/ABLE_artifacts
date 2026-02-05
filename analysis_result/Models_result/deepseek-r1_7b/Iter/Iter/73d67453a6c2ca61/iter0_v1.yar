rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass using conditional jumps"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 74 ?? ?? 1F } // Bypasses JNZ EAX 1F
        $pattern1 = { 75 ?? ?? } // Bypasses JZ 0x1824 by changing condition or offset
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? 85 C0 } // Bypasses a call with an addressable displacement

    condition:
        any of them
}