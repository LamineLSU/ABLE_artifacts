rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 E8 ?? ???? } // 9 bytes
        $pattern1 = { E8 ?? ?? ?? ?? 74 1A } // 7 bytes
        $pattern2 = { FF C4 8B 45 ?? ?? ?? } // 9 bytes

    condition:
        any of them
}