rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule - Disassembly analysis"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 05 C3 E8 ?? ?? ?? 8B C9 0F 84 }
        $pattern1 = { 07 ?? ?? ?? ?? E8 F4 FF }
        $pattern2 = { CC 81 FF ?? ?? ?? ?? E8 88 }

    condition:
        any of them
}