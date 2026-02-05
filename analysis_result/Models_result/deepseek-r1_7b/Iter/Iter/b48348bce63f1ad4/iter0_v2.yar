rule Bypass_Esc0n
{
    meta:
        description = "Evasion bypass via ExitProcess calls"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 F8 ?? 3E 70 ?? ?? 70 }
        $pattern1 = { E8 C1 FF FF ?? ?? ?? ?? FF D2 F8 ?? 00 00 00 00 }
        $pattern2 = { FF 75 08 ?? FF 15 5C C2 4C 00 ?? ?? ?? ?? }

    condition:
        any of them
}