rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 B4 92 39 00 48 83 EC 28 53 55 8B 6C 24 08 8B 45 0C } // CALL + Context - 16 bytes
        $pattern1 = { 84 C0 0F 84 ?? ?? ?? ?? 8B 45 ?? } // TEST + JZ + Context - 11 bytes
        $pattern2 = { 8B E5 5D 5E 8B E5 } // MOV ESP, EBP + Context - 8 bytes

    condition:
        any of them
}